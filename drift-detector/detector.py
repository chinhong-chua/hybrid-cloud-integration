"""Classify Terraform source changes before plan. No AWS calls or HCL evaluation."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import hcl2
from hcl2.utils import SerializationOptions


OPTIONS = SerializationOptions(with_comments=False, explicit_blocks=False,
                               preserve_heredocs=False, strip_string_quotes=True)
WORLD = {"0.0.0.0/0", "::/0"}
ENCRYPTION = {"encrypted", "storage_encrypted", "sqs_managed_sse_enabled",
              "kms_key_id", "kms_master_key_id", "sse_algorithm",
              "server_side_encryption_configuration", "server_side_encryption",
              "encryption_configuration", "encryption_at_rest"}
PUBLIC_BLOCK = {"block_public_acls", "block_public_policy", "ignore_public_acls",
                "restrict_public_buckets"}
NETWORK = ("security_group", "network_acl", "networkfirewall", "firewall")
LEVELS = {"low": 0, "medium": 1, "high": 2}


def fingerprint(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def walk(value, path=()):
    """Yield every nested value, retaining attribute names and list positions."""
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + (str(index),))


def strings(value):
    return [child for _, child in walk(value) if isinstance(child, str)]


def parse_source(text, path):
    if not text.strip():
        return {}
    try:
        if path.endswith(".json"):
            return json.loads(text)
        return hcl2.loads(text, serialization_options=OPTIONS)
    except Exception as exc:
        # Do not echo parser messages: they can contain source text or secrets.
        raise ValueError(f"Cannot parse {path} ({type(exc).__name__}); use a full-context diff.") from exc


def blocks(document):
    """Accept native HCL block lists and Terraform JSON block maps."""
    result = {}
    for kind in ("resource", "data"):
        groups = document.get(kind, [])
        if isinstance(groups, dict):
            groups = [groups]
        for group in groups:
            for resource_type, names in group.items():
                for name, body in names.items():
                    result[f"{kind}.{resource_type}.{name}"] = body
    remainder = {key: value for key, value in document.items()
                 if key not in {"resource", "data"}}
    if remainder:
        result["configuration"] = remainder
    return result


def statements(body):
    """Read literal IAM JSON, jsonencode objects, and policy-document blocks."""
    found, unresolved = [], False

    def visit(value, policy=False):
        nonlocal unresolved
        if isinstance(value, str):
            if not policy:
                return
            match = re.fullmatch(r"\$\{jsonencode\((.*)\)\}", value, re.S)
            if match:
                try:
                    visit(hcl2.loads("value = " + match[1], serialization_options=OPTIONS)["value"])
                except Exception:
                    unresolved = True
            elif value.lstrip().startswith("{"):
                try:
                    visit(json.loads(value))
                except ValueError:
                    unresolved = True
            else:
                unresolved = True
        elif isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in {"statement", "statement_list"}:
                    entries = child if isinstance(child, list) else [child]
                    for entry in entries:
                        if isinstance(entry, dict):
                            found.append({k.lower(): v for k, v in entry.items()})
                        else:
                            unresolved = True
                elif key.lower() in {"policy", "assume_role_policy", "inline_policy"}:
                    visit(child, policy=True)
                elif isinstance(child, (dict, list)):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child, policy=policy)

    visit(body)
    return found, unresolved


def assess(path, address, before, after):
    findings = []

    def add(rule, level, description, reason, recommendation):
        findings.append({"file": path, "address": address, "rule_id": rule,
                         "change_description": description, "risk_level": level,
                         "reasoning": reason, "recommendation": recommendation})

    old, new = before or {}, after or {}
    old_attrs, new_attrs = dict(walk(old)), dict(walk(new))
    for attr in old_attrs.keys() | new_attrs.keys():
        if not attr:
            continue
        previous, current = old_attrs.get(attr), new_attrs.get(attr)
        if previous == current:
            continue
        name = attr[-1]
        disabled = current is False or current is None or current == "" or current == [] or current == {}
        if name in ENCRYPTION and disabled and (previous is not None or current is False):
            add("encryption-weakened", "high", f"Encryption setting {name} removed or disabled",
                "An explicit encryption control is being removed or disabled; service defaults are not evaluated.",
                "Retain explicit encryption or review and document an equivalent replacement before merging.")
        if name in PUBLIC_BLOCK and disabled:
            add("public-access-control", "high", f"S3 public-access control {name} removed or disabled",
                "Removing a block can allow another ACL or policy to expose data.",
                "Keep all public-access blocks enabled unless a separately reviewed design requires otherwise.")
    if before is not None and after is None and any(word in address for word in
            ("encryption", "public_access_block")):
        add("security-resource-removed", "high", "Security-control resource removed",
            "The change deletes a resource responsible for encryption or public-access protection.",
            "Restore the control or review its replacement and migration before proceeding.")

    if any(word in address for word in NETWORK):
        old_objects = {fingerprint(v) for _, v in walk(old) if isinstance(v, dict)}
        for location, rule in walk(new):
            if not isinstance(rule, dict) or fingerprint(rule) in old_objects:
                continue
            cidrs = [v for key, value in rule.items() if key in
                     {"cidr_blocks", "ipv6_cidr_blocks", "cidr_block", "ipv6_cidr_block", "cidr_ipv4", "cidr_ipv6"}
                     for v in strings(value)]
            if not WORLD.intersection(cidrs):
                continue
            outbound = ("egress" in location or "egress" in address or
                        rule.get("type") == "egress" or rule.get("egress") is True)
            deny = rule.get("rule_action", rule.get("action")) == "deny"
            if not deny:
                add("public-network-access", "medium" if outbound else "high",
                    "Public egress rule changed" if outbound else "Public ingress rule introduced or changed",
                    "The changed rule includes the entire IPv4 or IPv6 internet; allowed ports and protocols require review.",
                    "Restrict source/destination ranges and ports to the intended clients and services.")
        add("network-change", "medium", "Network access configuration changed",
            "Rule ordering, references and connectivity effects need human review even without a literal public CIDR.",
            "Review direction, ports, protocol, rule ordering and referenced network values.")

    old_statements, old_unknown = statements(old)
    new_statements, new_unknown = statements(new)
    old_set = {fingerprint(item) for item in old_statements}
    new_set = {fingerprint(item) for item in new_statements}
    for item in new_statements:
        if fingerprint(item) in old_set or item.get("effect", "Allow").lower() == "deny":
            continue
        actions = strings(item.get("action", item.get("actions", [])))
        resources = strings(item.get("resource", item.get("resources", [])))
        if "*" in strings(item.get("principal", item.get("principals", []))):
            add("iam-public-principal", "high", "Public principal grant introduced or changed",
                "An Allow statement grants access to a wildcard principal; conditions are not evaluated as exceptions.",
                "Restrict principals to the intended identities or services and review conditions.")
        if any("*" in action or "?" in action for action in actions) or "*" in resources:
            add("iam-wildcard-allow", "high", "Wildcard IAM grant introduced or changed",
                "An Allow statement grants wildcard actions or all resources. Conditions are not evaluated as exceptions.",
                "Use explicit actions and scoped resource ARNs; review any unavoidable wildcard separately.")
        elif any("*" in resource or "?" in resource for resource in resources):
            add("iam-scoped-wildcard", "medium", "Scoped resource wildcard grant changed",
                "A path/prefix wildcard may be intentional but broadens the set of matching resources.",
                "Verify the prefix is restricted to the intended workload and client boundaries.")
        if "notaction" in item or "not_actions" in item or "notresource" in item or "not_resources" in item:
            add("iam-complement-grant", "high", "Complement-based IAM grant changed",
                "An Allow using NotAction or NotResource can grant a broad complement of permissions.",
                "Prefer explicit grants and review the complete effective policy.")
    if any(item.get("effect", "Allow").lower() == "deny" and fingerprint(item) not in new_set
           for item in old_statements):
        add("iam-deny-removed", "high", "Explicit Deny removed or changed",
            "A deny guardrail is removed or altered; equivalence cannot be proven statically.",
            "Retain the guardrail or review the replacement before merging.")
    if new_unknown or old_unknown:
        add("unresolved-policy", "medium", "Policy expression requires manual review",
            "The policy is not a supported literal JSON/jsonencode or policy-document statement.",
            "Inspect referenced files, variables and generated policy output in the subsequent plan.")
    if not findings:
        changed_keys = {key for key in old.keys() | new.keys() if old.get(key) != new.get(key)}
        cosmetic = (before is not None and after is not None and bool(changed_keys)
                    and changed_keys <= {"tags", "tags_all", "description"})
        add("metadata-change" if cosmetic else "unclassified-change", "low" if cosmetic else "medium",
            "Metadata changed" if cosmetic else "Configuration changed outside a specific rule",
            "Only tags/description changed in this block." if cosmetic else
            "No high-risk rule matched; expressions, variables, modules and other resource behavior are not evaluated.",
            "Review metadata conventions." if cosmetic else "Review the source and Terraform plan; this is not a safety guarantee.")
    # Nested encryption attributes can produce duplicate descriptions.
    return list({fingerprint(item): item for item in findings}.values())


def diff_files(text):
    """Reconstruct full-context before/after sources; accept the supplied rule excerpt."""
    files, current, inside = [], None, False
    for line in text.splitlines():
        if line.startswith("diff --git "):
            inside = False
        elif line.startswith("--- "):
            current = {"old_path": line[4:].split("\t")[0], "before": [], "after": [], "hunks": 0}
            files.append(current)
            inside = False
        elif line.startswith("+++ ") and current is not None:
            current["new_path"] = line[4:].split("\t")[0]
        elif line.startswith("@@ ") and current is not None:
            current["hunks"] += 1
            if current["hunks"] > 1:
                raise ValueError("Multiple partial hunks: regenerate with git diff --unified=1000000.")
            match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", line)
            if not match:
                raise ValueError("Invalid diff hunk header.")
            current["expected_before"] = int(match[2] or 1)
            current["expected_after"] = int(match[4] or 1)
            if max(int(match[1]), int(match[3])) > 1:
                header = match[5].strip()
                if not re.fullmatch(r'(?:resource|data) "[^"]+" "[^"]+" \{', header):
                    raise ValueError("Partial diff lacks a complete block; use a full-context diff.")
                current["before"].append(header)
                current["after"].append(header)
                current["excerpt"] = True
            inside = True
        elif inside and line.startswith((" ", "+", "-")):
            if line[0] != "+":
                current["before"].append(line[1:])
            if line[0] != "-":
                current["after"].append(line[1:])
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            raise ValueError("Binary configuration changes cannot be analysed.")
    if text.strip() and not files:
        raise ValueError("No supported unified diff found; empty input alone means no changes.")
    for item in files:
        if "new_path" not in item or not item["hunks"]:
            raise ValueError("Incomplete diff file headers or missing hunks.")
        if not item.get("excerpt") and (len(item["before"]) != item["expected_before"] or
                                        len(item["after"]) != item["expected_after"]):
            raise ValueError("Truncated or inconsistent diff hunk; regenerate a full-context diff.")
        raw_path = item["old_path"] if item["new_path"] == "/dev/null" else item["new_path"]
        if raw_path.startswith('"'):
            raw_path = json.loads(raw_path)
        item["path"] = raw_path[2:] if raw_path.startswith(("a/", "b/")) else raw_path
    return files


def analyse(text):
    findings, scanned, warnings = [], [], []
    for item in diff_files(text):
        path = item["path"]
        if not path.endswith((".tf", ".tfvars", ".hcl", ".json")) or path.endswith(".terraform.lock.hcl"):
            continue
        scanned.append(path)
        if item.get("excerpt"):
            warnings.append(f"{path}: only the supplied block excerpt was analysed.")
        old = blocks(parse_source("\n".join(item["before"]), path))
        new = blocks(parse_source("\n".join(item["after"]), path))
        for address in sorted(old.keys() | new.keys()):
            if old.get(address) != new.get(address):
                findings.extend(assess(path, address, old.get(address), new.get(address)))
    counts = {level: sum(item["risk_level"] == level for item in findings) for level in LEVELS}
    return {"schema_version": 1, "status": "blocked" if counts["high"] else "passed",
            "summary": counts, "files_scanned": sorted(set(scanned)), "warnings": warnings,
            "findings": findings}


def git(*args, input_text=None):
    result = subprocess.run(["git", *args], input=input_text, text=True,
                            encoding="utf-8", capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Git comparison failed; check revisions and fetch history. No scan was completed.")
    return result.stdout.strip() if args[0] in {"rev-parse", "hash-object"} else result.stdout


def source_diff(base, head):
    if base == "EMPTY" or re.fullmatch("0{40,64}", base):
        base_sha = git("hash-object", "-t", "tree", "--stdin", input_text="")
    else:
        base_sha = git("rev-parse", "--verify", "--end-of-options", base + "^{commit}")
    revisions = [base_sha]
    if head != "WORKTREE":
        revisions.append(git("rev-parse", "--verify", "--end-of-options", head + "^{commit}"))
    return git("-c", "core.quotePath=false", "diff", "--no-ext-diff", "--no-textconv",
               "--no-renames", "--no-color", "--unified=1000000", *revisions, "--",
               "*.tf", "*.tfvars", "*.hcl", "*.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff", type=Path, help="Full-context unified diff (UTF-8)")
    source.add_argument("--base", help="Base commit/ref; EMPTY for an initial commit")
    parser.add_argument("--head", default="HEAD", help="Head commit/ref or WORKTREE (tracked files only)")
    parser.add_argument("--output", type=Path, help="Write the JSON report as well as stdout")
    args = parser.parse_args(argv)
    try:
        text = args.diff.read_text(encoding="utf-8-sig") if args.diff else source_diff(args.base, args.head)
        report = analyse(text)
        if args.base:
            report["comparison"] = {"base": args.base, "head": args.head}
        code = 1 if report["status"] == "blocked" else 0
    except (ValueError, OSError, TypeError, AttributeError) as exc:
        report = {"schema_version": 1, "status": "error", "findings": [],
                  "error": str(exc) if isinstance(exc, ValueError) else
                  "Input could not be processed; check files and supported document structure."}
        code = 2
    rendered = json.dumps(report, indent=2, ensure_ascii=True)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError:
            rendered = json.dumps({"schema_version": 1, "status": "error", "findings": [],
                                   "error": "Could not write the report; check output permissions."})
            code = 2
    print(rendered)
    return code


if __name__ == "__main__":
    sys.exit(main())
