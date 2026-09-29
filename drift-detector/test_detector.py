import contextlib
import difflib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import detector


FIXTURES = Path(__file__).parent / "fixtures"


def change(before, after, path="infra/main.tf"):
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                      fromfile="a/" + path, tofile="b/" + path, n=1000000))


def report(before, after, path="infra/main.tf"):
    return detector.analyse(change(before, after, path))


class RiskTests(unittest.TestCase):
    def test_fixture_risk_levels(self):
        for name, level in [("public-ingress", "high"), ("wildcard-iam", "high"),
                            ("encryption-disabled", "high"), ("network-acl", "medium"),
                            ("metadata-only", "low"), ("explicit-deny", "medium")]:
            with self.subTest(name=name):
                result = detector.analyse((FIXTURES / (name + ".diff")).read_text())
                self.assertGreater(result["summary"][level], 0)
                self.assertEqual(result["status"], "blocked" if level == "high" else "passed")
                for finding in result["findings"]:
                    self.assertTrue(all(finding[key] for key in
                        ("change_description", "risk_level", "reasoning", "recommendation")))

    def test_changed_public_rule_is_conservatively_blocked(self):
        before = 'resource "aws_security_group_rule" "x" {\n type="ingress"\n cidr_blocks=["0.0.0.0/0"]\n description="old"\n}\n'
        result = report(before, before.replace('"old"', '"new"'))
        # The changed public rule must still be reviewed: the scanner is conservative.
        self.assertEqual(result["status"], "blocked")

    def test_unchanged_separate_public_rule_does_not_block(self):
        public = 'resource "aws_security_group_rule" "x" {\n cidr_blocks=["0.0.0.0/0"]\n}\n'
        before = public + 'resource "aws_sqs_queue" "x" {\n tags={Owner="old"}\n}\n'
        self.assertEqual(report(before, before.replace('"old"', '"new"'))["summary"]["high"], 0)

    def test_ipv6_inline_ingress(self):
        after = 'resource "aws_security_group" "x" {\n ingress {\n ipv6_cidr_blocks=["::/0"]\n }\n}\n'
        self.assertEqual(report("", after)["status"], "blocked")

    def test_public_egress_is_medium(self):
        after = 'resource "aws_vpc_security_group_egress_rule" "x" {\n cidr_ipv4="0.0.0.0/0"\n}\n'
        self.assertEqual(report("", after)["status"], "passed")
        self.assertGreater(report("", after)["summary"]["medium"], 0)

    def test_public_acl_deny_not_public_allow(self):
        after = 'resource "aws_network_acl_rule" "x" {\n cidr_block="0.0.0.0/0"\n rule_action="deny"\n}\n'
        self.assertEqual(report("", after)["summary"]["high"], 0)

    def test_explicit_deny_removed(self):
        before = 'resource "aws_iam_policy" "x" {\n policy=jsonencode({Statement=[{Effect="Deny",Action="*",Resource="*"}]})\n}\n'
        self.assertIn("iam-deny-removed", [x["rule_id"] for x in report(before, "")["findings"]])

    def test_allow_to_deny_does_not_flag_wildcard_allow(self):
        before = 'resource "aws_iam_policy" "x" {\n policy=jsonencode({Statement=[{Effect="Allow",Action="*",Resource="*"}]})\n}\n'
        self.assertEqual(report(before, before.replace('"Allow"', '"Deny"'))["summary"]["high"], 0)

    def test_policy_document_default_effect_allow(self):
        after = 'data "aws_iam_policy_document" "x" {\n statement {\n actions=["iam:*"]\n resources=["*"]\n }\n}\n'
        self.assertEqual(report("", after)["status"], "blocked")

    def test_json_policy_multiline(self):
        after = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}, indent=2) + "\n"
        self.assertEqual(report("", after, "infra/policy.json")["status"], "blocked")

    def test_terraform_json(self):
        after = json.dumps({"resource": {"aws_sqs_queue": {"x": {"sqs_managed_sse_enabled": False}}}}) + "\n"
        self.assertEqual(report("", after, "infra/main.tf.json")["status"], "blocked")

    def test_unresolved_policy_is_not_called_safe(self):
        after = 'resource "aws_iam_policy" "x" {\n policy=file(var.policy_file)\n}\n'
        result = report("", after)
        self.assertIn("unresolved-policy", [x["rule_id"] for x in result["findings"]])
        self.assertEqual(result["summary"]["low"], 0)

    def test_dependency_list_is_not_a_policy(self):
        after = 'resource "aws_s3_bucket_notification" "x" {\n depends_on=[aws_sqs_queue_policy.input]\n}\n'
        self.assertNotIn("unresolved-policy", [x["rule_id"] for x in report("", after)["findings"]])

    def test_empty_new_block_is_not_metadata(self):
        self.assertEqual(report("", 'data "aws_caller_identity" "x" {}\n')["summary"]["low"], 0)

    def test_public_principal(self):
        after = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/file", "Principal": "*"}]}) + "\n"
        self.assertIn("iam-public-principal", [x["rule_id"] for x in report("", after, "infra/policy.json")["findings"]])

    def test_not_action_grant(self):
        after = json.dumps({"Statement": [{"Effect": "Allow", "NotAction": "iam:DeleteRole", "Resource": "arn:aws:iam::123456789012:role/demo"}]}) + "\n"
        self.assertIn("iam-complement-grant", [x["rule_id"] for x in report("", after, "infra/policy.json")["findings"]])

    def test_scoped_resource_wildcard_is_medium(self):
        after = 'resource "aws_iam_policy" "x" {\n policy=jsonencode({Statement=[{Effect="Allow",Action="s3:GetObject",Resource="arn:aws:s3:::example/incoming/*"}]})\n}\n'
        self.assertEqual(report("", after)["summary"], {"low": 0, "medium": 1, "high": 0})

    def test_encryption_resource_deletion(self):
        before = 'resource "aws_s3_bucket_server_side_encryption_configuration" "x" {\n bucket="example"\n}\n'
        self.assertEqual(report(before, "")["status"], "blocked")

    def test_public_access_flag_removed(self):
        before = 'resource "aws_s3_bucket_public_access_block" "x" {\n block_public_policy=true\n}\n'
        after = 'resource "aws_s3_bucket_public_access_block" "x" {\n}\n'
        self.assertEqual(report(before, after)["status"], "blocked")

    def test_comment_and_formatting_only(self):
        before = 'resource "aws_sqs_queue" "x" {\n name="example"\n}\n'
        after = '# Action="*" cidr_blocks=["0.0.0.0/0"]\nresource "aws_sqs_queue" "x" {\n name = "example" # safe comment\n}\n'
        self.assertEqual(report(before, after)["findings"], [])

    def test_non_security_variable_change_is_manual_review(self):
        before = 'variable "allowed_cidr" {\n default="10.0.0.0/8"\n}\n'
        after = before.replace("10.0.0.0/8", "0.0.0.0/0")
        self.assertEqual(report(before, after)["summary"], {"low": 0, "medium": 1, "high": 0})

    def test_supplied_excerpt(self):
        diff = '--- a/infra/security_group.tf\n+++ b/infra/security_group.tf\n@@ -10,7 +10,7 @@ resource "aws_security_group_rule" "allow_api" {\n   type = "ingress"\n-  cidr_blocks = ["10.0.0.0/8"]\n+  cidr_blocks = ["0.0.0.0/0"]\n }\n'
        result = detector.analyse(diff)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["warnings"])

    def test_empty_diff(self):
        self.assertEqual(detector.analyse("")["findings"], [])

    def test_partial_diff_without_block_header_fails(self):
        with self.assertRaises(ValueError):
            detector.analyse('--- a/x.tf\n+++ b/x.tf\n@@ -5 +5 @@\n-name="a"\n+name="b"\n')

    def test_multiple_partial_hunks_fail(self):
        with self.assertRaises(ValueError):
            detector.analyse('--- a/x.tf\n+++ b/x.tf\n@@ -1 +1 @@\n-a=1\n+a=2\n@@ -8 +8 @@\n-b=1\n+b=2\n')

    def test_truncated_diff_fails_even_if_remaining_hcl_is_valid(self):
        with self.assertRaises(ValueError):
            detector.analyse('--- a/x.tf\n+++ b/x.tf\n@@ -1,10 +1,10 @@\n-name="a"\n+name="b"\n')

    def test_literal_json_and_heredoc_policy(self):
        policy = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        values = [json.dumps(policy), "<<POLICY\n" + policy + "\nPOLICY"]
        for value in values:
            with self.subTest(value=value):
                after = 'resource "aws_iam_policy" "x" {\n policy=' + value + '\n}\n'
                self.assertEqual(report("", after)["status"], "blocked")

    def test_git_comparison_includes_all_commits_and_worktree(self):
        with tempfile.TemporaryDirectory() as folder:
            original = Path.cwd()
            try:
                os.chdir(folder)
                def run(*args):
                    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()
                def commit(message):
                    run("add", "main.tf")
                    run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", message)
                    return run("rev-parse", "HEAD")
                run("init")
                source = Path("main.tf")
                safe = 'resource "aws_sqs_queue" "x" {\n sqs_managed_sse_enabled=true\n}\n'
                source.write_text(safe)
                base = commit("safe baseline")
                self.assertEqual(detector.analyse(detector.source_diff("0" * 40, "HEAD"))["summary"]["high"], 0)
                source.write_text(safe.replace("true", "false"))
                commit("disable encryption")
                source.write_text(source.read_text() + "# later comment\n")
                commit("comment only")
                self.assertEqual(detector.analyse(detector.source_diff(base, "HEAD"))["status"], "blocked")
                self.assertEqual(detector.analyse(detector.source_diff("HEAD^", "HEAD"))["findings"], [])
                source.write_text(safe)
                self.assertEqual(detector.analyse(detector.source_diff("HEAD", "WORKTREE"))["summary"]["high"], 0)
                with self.assertRaises(ValueError):
                    detector.source_diff("missing-ref", "HEAD")
            finally:
                os.chdir(original)

    def test_cli_exit_codes_and_report(self):
        for name, expected in [("public-ingress", 1), ("metadata-only", 0)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                output = Path(folder) / "report.json"
                with contextlib.redirect_stdout(io.StringIO()):
                    code = detector.main(["--diff", str(FIXTURES / (name + ".diff")), "--output", str(output)])
                self.assertEqual(code, expected)
                self.assertTrue(json.loads(output.read_text())["findings"])

    def test_malformed_input_exit_two_without_source_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "bad.diff"
            source.write_text('--- a/x.tf\n+++ b/x.tf\n@@ -0,0 +1,1 @@\n+token = "example-private-value\n')
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = detector.main(["--diff", str(source)])
            self.assertEqual(code, 2)
            self.assertNotIn("example-private-value", buffer.getvalue())
            self.assertEqual(json.loads(buffer.getvalue())["status"], "error")


if __name__ == "__main__":
    unittest.main()
