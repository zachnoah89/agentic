#!/usr/bin/env python3
"""Comprehensive test suite for MCP server and security engine."""

import json
import os
import subprocess
import sys
import unittest

SERVER_PY = os.path.join(os.path.dirname(__file__), "server.py")
TEST_LAB = "overprivileged-vertex-agent"


def call_mcp(requests):
    proc = subprocess.Popen(
        [sys.executable, SERVER_PY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    input_data = "\n".join(json.dumps(r) for r in requests) + "\n"
    stdout_data, stderr_data = proc.communicate(input=input_data, timeout=10)
    lines = [json.loads(l.strip()) for l in stdout_data.strip().split("\n") if l.strip()]
    return proc.returncode, lines, stderr_data


class TestMCPServer(unittest.TestCase):
    def test_tools_list(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        code, resps, stderr = call_mcp(reqs)
        self.assertEqual(code, 0)
        self.assertEqual(len(resps), 2)
        tools = resps[1]["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        expected = [
            "ping",
            "recommend_iam_roles",
            "lookup_roles",
            "explain_pitfall",
            "classify_lab",
            "audit_lab",
            "validate_pre_merge",
            "get_fleet_status",
            "get_backlog",
            "apply_security_patch",
            "record_pitfall",
            "check_exception",
        ]
        for exp in expected:
            self.assertIn(exp, tool_names)

    def test_audit_lab(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "audit_lab", "arguments": {"lab_slug": TEST_LAB}},
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertEqual(content["lab_slug"], TEST_LAB)
        self.assertGreater(content["total_findings"], 0)
        rule_ids = [f["rule_id"] for f in content["findings"]]
        self.assertIn("CRITICAL_ROLE_EDITOR", rule_ids)
        self.assertIn("DEV_ADMIN_PRESENT", rule_ids)

    def test_recommend_iam_roles(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "recommend_iam_roles", "arguments": {"lab_slug": TEST_LAB}},
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertEqual(content["lab_slug"], TEST_LAB)
        self.assertIn("roles/editor", content["roles_to_remove"])
        rec_roles = [r["role"] for r in content["recommended_roles"]]
        self.assertIn("roles/viewer", rec_roles)
        self.assertIn("roles/serviceusage.serviceUsageConsumer", rec_roles)

    def test_validate_pre_merge_fails_on_unhardened(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "validate_pre_merge", "arguments": {"lab_slug": TEST_LAB}},
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertEqual(content["status"], "FAIL")
        self.assertGreater(content["blocking_violations_count"], 0)

    def test_apply_security_patch_dry_run(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "apply_security_patch",
                    "arguments": {
                        "lab_slug": TEST_LAB,
                        "patch_type": "egress_firewall",
                        "dry_run": True,
                    },
                },
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertTrue(content["dry_run"])
        self.assertGreaterEqual(len(content["diffs"]), 1)
        self.assertIn("deny-all-egress", content["diffs"][0]["diff"])

    def test_minilab_deceptive_iam_and_cloud_terminal(self):
        import tempfile
        import shutil
        from security_engine import SecurityEngine

        tmp_dir = tempfile.mkdtemp()
        try:
            lab_dir = os.path.join(tmp_dir, "labs", "mock-minilab-terminal")
            tf_dir = os.path.join(lab_dir, "tf")
            os.makedirs(tf_dir, exist_ok=True)
            with open(os.path.join(lab_dir, "sandbox.yaml"), "w") as f:
                f.write("""schema_version: 2
environment:
  resources:
  - type: gcp_project
    id: project_0
    policy_tier: genai_sandbox
  - type: cloud_terminal
    id: terminal_0
  student_visible_outputs:
  - label: Open Terminal
    reference: terminal_0.url
""")
            with open(os.path.join(tf_dir, "main.tf"), "w") as f:
                f.write("""resource "google_project_iam_custom_role" "no_vm_create" {
  role_id     = "noVmCreate"
  title       = "No VM Create"
  permissions = ["compute.instanceTemplates.create", "compute.instanceGroupManagers.create"]
}

resource "google_project_iam_policy" "lockdown" {
  project     = var.gcp_project_id
  policy_data = data.google_iam_policy.student.policy_data
}

resource "google_compute_instance" "lab_vm" {
  name         = "lab-vm"
  machine_type = "e2-medium"
}
""")
            engine = SecurityEngine(
                plugin_dir=os.path.dirname(os.path.dirname(__file__)),
                lab_repo_root=tmp_dir,
            )
            res = engine.audit_lab("mock-minilab-terminal")
            codes = {f["rule_id"] for f in res["findings"]}
            self.assertIn("MANAGED_IDE_ON_GENAI_TIER", codes)
            self.assertIn("TF_AUTHORITATIVE_POLICY_OMITS_ORCHESTRATOR", codes)
            self.assertIn("TF_CUSTOM_ROLE_NOVMCREATE_MIG_BYPASS", codes)
            self.assertIn("TF_DEFAULT_COMPUTE_SA_EDITOR_EXPOSURE", codes)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_get_backlog(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "get_backlog", "arguments": {"limit": 3}},
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertGreaterEqual(len(content["backlog"]), 2)
        self.assertGreaterEqual(content["backlog"][0]["risk_score"], content["backlog"][1]["risk_score"])

    def test_record_pitfall(self):
        test_id = "test-temp-unit-pitfall"
        kb_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "kb", "pitfalls.yaml")
        try:
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "record_pitfall",
                        "arguments": {
                            "lab_slug": TEST_LAB,
                            "pitfall_id": test_id,
                            "symptom": "Unit test symptom",
                            "cause": "Unit test cause",
                            "fix": "Unit test fix",
                            "required_role": "roles/compute.viewer",
                        },
                    },
                },
            ]
            code, resps, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            content = json.loads(resps[1]["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "RECORDED")
            self.assertEqual(content["pitfall_id"], test_id)

            # Test deduplication
            code2, resps2, _ = call_mcp(reqs)
            content2 = json.loads(resps2[1]["result"]["content"][0]["text"])
            self.assertEqual(content2["status"], "EXISTS")
        finally:
            # Clean up test entry from kb/pitfalls.yaml
            if os.path.exists(kb_file):
                with open(kb_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                cleaned = []
                skipping = False
                for line in lines:
                    if f"id: {test_id}" in line:
                        skipping = True
                        continue
                    if skipping and line.startswith("  - id:"):
                        skipping = False
                    if not skipping:
                        cleaned.append(line)
                with open(kb_file, "w", encoding="utf-8") as f:
                    f.writelines(cleaned)

    def test_check_exception(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "check_exception", "arguments": {"lab_slug": "iam-ctf-privilege-escalation-challenge"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "check_exception", "arguments": {"lab_slug": "unexempt-lab"}},
            },
        ]
        code, resps, _ = call_mcp(reqs)
        self.assertEqual(code, 0)
        content_exempt = json.loads(resps[1]["result"]["content"][0]["text"])
        self.assertTrue(content_exempt["is_exempt"])
        self.assertEqual(content_exempt["status"], "APPROVED_EXCEPTION")

        content_unexempt = json.loads(resps[2]["result"]["content"][0]["text"])
        self.assertFalse(content_unexempt["is_exempt"])
        self.assertEqual(content_unexempt["status"], "NOT_EXEMPT")

    def test_managed_ide_and_sa_key_on_genai_sandbox(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "sandbox.yaml"), "w") as f:
                f.write(
                    "schema_version: 2\n"
                    "environment:\n"
                    "  resources:\n"
                    "    - type: gcp_project\n"
                    "      id: project_0\n"
                    "      policy_tier: genai_sandbox\n"
                    "    - type: ide\n"
                    "      id: ide_0\n"
                )
            tf_dir = os.path.join(tmpdir, "tf")
            os.makedirs(tf_dir, exist_ok=True)
            with open(os.path.join(tf_dir, "main.tf"), "w") as f:
                f.write(
                    'resource "google_service_account_key" "bad_key" {\n'
                    '  service_account_id = "my-sa"\n'
                    '}\n'
                )
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "validate_pre_merge", "arguments": {"lab_slug": tmpdir}},
                },
            ]
            code, resps, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            content = json.loads(resps[1]["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "FAIL")
            rule_ids = [v["rule_id"] for v in content["blocking_violations"]]
            self.assertIn("MANAGED_IDE_ON_GENAI_TIER", rule_ids)
            self.assertIn("SA_KEY_WITH_LLM_OR_BROAD_ROLE", rule_ids)

    def test_minilab_deceptive_iam_and_cloud_terminal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            qy_path = os.path.join(tmpdir, "sandbox.yaml")
            with open(qy_path, "w", encoding="utf-8") as f:
                f.write(
                    "environment:\n"
                    "  cloud_terminal: true\n"
                    "  resources:\n"
                    "    - type: gcp_user\n"
                    "      id: user_0\n"
                    "      permissions:\n"
                    "        - project: project_0\n"
                    "          roles:\n"
                    "            - roles/viewer\n"
                )
            tf_dir = os.path.join(tmpdir, "terraform-files")
            os.makedirs(tf_dir, exist_ok=True)
            with open(os.path.join(tf_dir, "main.tf"), "w", encoding="utf-8") as f:
                f.write(
                    'resource "google_project_iam_policy" "project" {\n'
                    '  project     = var.project_id\n'
                    '  policy_data = data.google_iam_policy.admin.policy_data\n'
                    '}\n'
                    'data "google_iam_policy" "admin" {\n'
                    '  binding {\n'
                    '    role    = "roles/owner"\n'
                    '    members = ["user:${var.username}"]\n'
                    '  }\n'
                    '}\n'
                )
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "audit_lab", "arguments": {"lab_slug": tmpdir}},
                },
            ]
            code, resps, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            audit_res = json.loads(resps[1]["result"]["content"][0]["text"])
            rule_ids = {f["rule_id"] for f in audit_res.get("findings", [])}
            self.assertIn("MINILAB_CLOUD_TERMINAL_ENABLED", rule_ids)
            self.assertIn("TF_DECEPTIVE_IAM_POLICY_OVERRIDE", rule_ids)
            self.assertIn("TF_AUTHORITATIVE_POLICY_OMITS_ORCHESTRATOR", rule_ids)

    def test_missing_runtime_yaml_audit_and_patch(self):
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as tmpdir:
            qy_path = os.path.join(tmpdir, "sandbox.yaml")
            with open(qy_path, "w", encoding="utf-8") as f:
                f.write(
                    "schema_version: 2\n"
                    "environment:\n"
                    "  resources:\n"
                    "    - type: gcp_project\n"
                    "      id: project_0\n"
                    "      startup_script:\n"
                    "        type: sandbox-platform\n"
                    "        path: tf\n"
                    "    - type: gcp_user\n"
                    "      id: user_0\n"
                    "      permissions:\n"
                    "        - project: project_0\n"
                    "          roles:\n"
                    "            - roles/viewer\n"
                )
            tf_dir = os.path.join(tmpdir, "tf")
            os.makedirs(tf_dir, exist_ok=True)
            with open(os.path.join(tf_dir, "main.tf"), "w", encoding="utf-8") as f:
                f.write('resource "google_compute_network" "custom" { name = "custom-net" }\n')

            # 1. Audit should flag MISSING_RUNTIME_YAML as CRITICAL
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "audit_lab", "arguments": {"lab_slug": tmpdir}},
                },
            ]
            code, resps, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            audit_res = json.loads(resps[1]["result"]["content"][0]["text"])
            rule_ids = {f["rule_id"] for f in audit_res.get("findings", [])}
            self.assertIn("MISSING_RUNTIME_YAML", rule_ids)
            crit = [f for f in audit_res.get("findings", []) if f["rule_id"] == "MISSING_RUNTIME_YAML"]
            self.assertEqual(crit[0]["severity"], "CRITICAL")

            # 2. validate_pre_merge should FAIL
            reqs_v = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "validate_pre_merge", "arguments": {"lab_slug": tmpdir}},
                },
            ]
            code, resps_v, _ = call_mcp(reqs_v)
            self.assertEqual(code, 0)
            val_res = json.loads(resps_v[1]["result"]["content"][0]["text"])
            self.assertEqual(val_res["status"], "FAIL")
            blocking_rules = {f["rule_id"] for f in val_res.get("blocking_violations", [])}
            self.assertIn("MISSING_RUNTIME_YAML", blocking_rules)

            # 3. Dry-run apply_security_patch with runtime_yaml
            reqs_p_dry = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "apply_security_patch",
                        "arguments": {
                            "lab_slug": tmpdir,
                            "patch_type": "runtime_yaml",
                            "dry_run": True,
                        },
                    },
                },
            ]
            code, resps_p_dry, _ = call_mcp(reqs_p_dry)
            self.assertEqual(code, 0)
            patch_dry_res = json.loads(resps_p_dry[1]["result"]["content"][0]["text"])
            self.assertTrue(patch_dry_res["dry_run"])
            self.assertEqual(len(patch_dry_res["diffs"]), 1)
            self.assertFalse(os.path.exists(os.path.join(tf_dir, "runtime.yaml")))

            # 4. Live apply_security_patch with runtime_yaml
            reqs_p_live = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "apply_security_patch",
                        "arguments": {
                            "lab_slug": tmpdir,
                            "patch_type": "runtime_yaml",
                            "dry_run": False,
                        },
                    },
                },
            ]
            code, resps_p_live, _ = call_mcp(reqs_p_live)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(tf_dir, "runtime.yaml")))
            with open(os.path.join(tf_dir, "runtime.yaml"), "r", encoding="utf-8") as f:
                r_content = f.read()
            self.assertIn("runtime: terraform", r_content)
            self.assertIn("version: 1.12.1", r_content)

            # 5. Audit should now be clean of MISSING_RUNTIME_YAML
            code, resps_after, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            audit_after = json.loads(resps_after[1]["result"]["content"][0]["text"])
            after_rules = {f["rule_id"] for f in audit_after.get("findings", [])}
            self.assertNotIn("MISSING_RUNTIME_YAML", after_rules)

    def test_egress_firewall_auto_scaffolds_runtime_yaml(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_dir = os.path.join(tmpdir, "tf")
            os.makedirs(tf_dir, exist_ok=True)
            with open(os.path.join(tf_dir, "main.tf"), "w", encoding="utf-8") as f:
                f.write('resource "google_compute_network" "net" { name = "net" }\n')

            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "apply_security_patch",
                        "arguments": {
                            "lab_slug": tmpdir,
                            "patch_type": "egress_firewall",
                            "dry_run": False,
                        },
                    },
                },
            ]
            code, resps, _ = call_mcp(reqs)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(tf_dir, "secure_network.tf")))
            self.assertTrue(os.path.exists(os.path.join(tf_dir, "runtime.yaml")))
            with open(os.path.join(tf_dir, "runtime.yaml"), "r", encoding="utf-8") as f:
                r_content = f.read()
            self.assertIn("runtime: terraform", r_content)


if __name__ == "__main__":
    unittest.main()
