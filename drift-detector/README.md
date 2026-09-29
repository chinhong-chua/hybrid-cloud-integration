# Terraform source-change risk detector

This tool reviews configuration changes **before Terraform plan**, without AWS credentials. It reads a Git diff, reconstructs before/after HCL or JSON, compares changed blocks, and emits a JSON risk report. It does not detect live AWS drift or replace Terraform plan.

## Run locally

From the repository root, using Python 3.10 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r drift-detector/requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s drift-detector -p 'test_*.py' -v
```

Demonstrate a high-risk change without touching infrastructure:

```powershell
.\.venv\Scripts\python.exe drift-detector/detector.py --diff drift-detector/fixtures/public-ingress.diff --output drift-detector/output/risk-report.json
$LASTEXITCODE # 1 is expected: this fixture is intentionally dangerous.
```

Compare committed revisions or tracked local edits:

```powershell
.\.venv\Scripts\python.exe drift-detector/detector.py --base 'HEAD^' --head HEAD
.\.venv\Scripts\python.exe drift-detector/detector.py --base HEAD --head WORKTREE
```

`WORKTREE` includes staged and unstaged changes to tracked files, but **not untracked files**. Use committed comparisons in CI. For an initial commit use `--base EMPTY`. References must exist locally; shallow or missing history is an error rather than a successful empty scan.

## Rules and results

| Change | Risk |
| --- | --- |
| Changed inbound SG/ACL rule with `0.0.0.0/0` or `::/0` and no explicit deny | High |
| Changed Allow statement with wildcard actions, `Resource = "*"`, wildcard principal, or NotAction/NotResource | High |
| Removed/disabled explicit encryption or S3 public-access protection | High |
| Removed or changed explicit IAM Deny | High; equivalence requires review |
| Scoped resource wildcard, public egress, other ACL/firewall/network changes | Medium |
| Unresolved policy expressions, variable/module changes, other unclassified changes | Medium |
| Only tags/description changed in an existing non-network block | Low |
| Formatting/comments only | No semantic finding |

Wildcards in an explicit Deny are not classified as permission grants. A changed rule already open to the internet is conservatively high even if its edit looks cosmetic. The same unchanged rule in a different block is not reported. Removing encryption can be flagged even if AWS would supply a default; the check protects explicit configuration, not inferred service behavior.

| Exit | Meaning | CI effect |
| --- | --- | --- |
| `0` | No high findings; medium findings still require review | Plan may proceed |
| `1` | At least one high finding | Plan blocked |
| `2` | Input, parsing, Git comparison or report-write error | Plan blocked |

Every finding includes `change_description`, `risk_level`, `reasoning` and `recommendation`, plus a file, block address and rule ID. The report includes counts by severity and scanned files. It contains no raw diff or policy bodies, though paths and resource identifiers remain visible. `passed` means this check found no blocking rule, not that the change is proven safe.

## CI integration

The local [workflow change](../.github/workflows/terraform.yml) adds `risk_check` alongside `checks`; `plan` needs both. The risk job installs the parser, runs tests, scans the comparison and uploads `risk-report.json` even when a high finding blocks the job. It has no AWS credentials. The existing environment approval still controls apply.

| Trigger | Comparison |
| --- | --- |
| Pull request | Event base SHA to GitHub's tested merge SHA |
| Push | SHA before the push to the pushed SHA, covering all commits in that push |
| Manual run | `base_ref` input to selected commit; default `HEAD^` |
| First push | Empty tree to pushed SHA |

Fetch depth is zero. For manual runs choose the actual reviewed baseline; `HEAD^` only checks the latest commit and is not automatically the last deployed commit. Shell arguments use quoted environment variables, and the Python tool resolves refs without executing a shell.

High findings require source correction and review before rerunning. There is no automatic bypass or allowlist. A legitimate exception would require an explicitly reviewed rule/design change. Changes to the detector and workflow themselves require code review; the check is not protected against someone authorized to rewrite its rules. No hosted run of these Task 6 changes has been performed yet.

## Fixtures and coverage

The `fixtures/` directory contains public ingress, wildcard IAM, disabled encryption, ACL changes, metadata-only changes and an explicit Deny example. Tests also cover IPv6, JSON policies, heredocs, Terraform JSON, unresolved policies, removed controls, comments, error reporting and actual Git comparisons across multiple commits.

The `--base` mode generates a full-context diff automatically. Supplied `--diff` files should also use `git diff --unified=1000000 --no-renames --no-color`. Multiple partial hunks or truncated full-context input fail. A single complete resource excerpt identified by its hunk header is supported for the sample fixture format, with a coverage warning.

Supported file suffixes are `.tf`, `.tfvars`, `.hcl` and `.json`; the provider lock file is excluded. HCL parsing uses [python-hcl2](https://github.com/amplify-education/python-hcl2), not expression evaluation. The tool does not resolve variables, locals, modules, remote policy documents, dynamic blocks or IAM conditions. Those changes can be medium rather than high. Inline source rules cannot establish effective AWS permissions, actual reachability or application safety. Review the subsequent Terraform plan and retain normal deployment approval.

This is a deterministic rule-based implementation. No LLM or external classification service is used.
