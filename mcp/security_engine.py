#!/usr/bin/env python3
"""Security Engine for Cloud Lab hardening and compliance.

Provides deterministic auditing, role recommendation, knowledge-base querying,
pre-merge gating, dynamic fleet scanning, backlog prioritization, and patching.
Strictly zero-external-dependencies (PyYAML + stdlib).
"""

import difflib
import glob
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger("cloud-sandbox-security-engine")

# ---------------------------------------------------------------------------
# Path Resolution Helpers
# ---------------------------------------------------------------------------


def resolve_lab_dir(lab_identifier: str, lab_repo_root: str) -> str:
    """Resolves a slug or path into an absolute lab directory."""
    if os.path.isabs(lab_identifier) and os.path.isdir(lab_identifier):
        return os.path.abspath(lab_identifier)

    # Check relative to current working directory
    if os.path.isdir(lab_identifier):
        return os.path.abspath(lab_identifier)

    # Check under lab_repo_root / sandboxes / <lab_identifier> or labs / <lab_identifier>
    for subdir in ("sandboxes", "labs"):
        candidate = os.path.join(lab_repo_root, subdir, lab_identifier)
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)

    # Check under lab_repo_root / <lab_identifier>
    candidate_direct = os.path.join(lab_repo_root, lab_identifier)
    if os.path.isdir(candidate_direct):
        return os.path.abspath(candidate_direct)

    raise FileNotFoundError(
        f"Could not locate sandbox directory for '{lab_identifier}'. Searched directly and under '{os.path.join(lab_repo_root, 'sandboxes')}'."
    )


def load_kb_yaml(file_path: str) -> Dict[str, Any]:
    """Safely loads a YAML knowledge base file."""
    if not os.path.exists(file_path):
        logger.warning(f"KB file not found: {file_path}")
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Failed to parse KB YAML '{file_path}': {e}")
        return {}


# ---------------------------------------------------------------------------
# Core Engine Class
# ---------------------------------------------------------------------------


class SecurityEngine:
    def __init__(self, plugin_dir: str, lab_repo_root: str):
        self.plugin_dir = plugin_dir
        self.kb_dir = os.path.join(plugin_dir, "kb")
        self.assets_dir = os.path.join(plugin_dir, "assets")
        self.lab_repo_root = lab_repo_root

        # Load knowledge base data
        self.roles_kb = load_kb_yaml(os.path.join(self.kb_dir, "roles.yaml")).get("roles", [])
        self.archetypes_kb = load_kb_yaml(os.path.join(self.kb_dir, "archetypes.yaml")).get(
            "archetypes", []
        )
        self.pitfalls_kb = load_kb_yaml(os.path.join(self.kb_dir, "pitfalls.yaml")).get(
            "pitfalls", []
        )
        self.exceptions_kb = load_kb_yaml(os.path.join(self.kb_dir, "exceptions.yaml")).get(
            "exceptions", []
        )

    def find_tf_dirs(self, lab_dir: str) -> List[str]:
        """Discovers all directories containing Terraform configurations (.tf) in a lab bundle."""
        tf_dirs = []
        candidates = ["tf", "terraform", "cleanup", "setup", "teardown", "blue", "green"]
        for c in candidates:
            d = os.path.join(lab_dir, c)
            if os.path.isdir(d):
                try:
                    if any(f.endswith(".tf") for f in os.listdir(d)):
                        tf_dirs.append(d)
                except Exception:
                    pass
        # Check subdirectories matching tf-* or terraform-* (e.g. multi-project harnesses)
        try:
            for item in sorted(os.listdir(lab_dir)):
                d = os.path.join(lab_dir, item)
                if os.path.isdir(d) and d not in tf_dirs:
                    if item.startswith(("tf-", "tf_", "terraform-", "terraform_")):
                        if any(f.endswith(".tf") for f in os.listdir(d)):
                            tf_dirs.append(d)
        except Exception:
            pass
        # Check lab root if .tf files exist at top level
        try:
            if any(f.endswith(".tf") for f in os.listdir(lab_dir) if os.path.isfile(os.path.join(lab_dir, f))):
                if lab_dir not in tf_dirs:
                    tf_dirs.append(lab_dir)
        except Exception:
            pass

        # Check directories referenced in sandbox.yaml (startup_script / cleanup_script)
        qy_path = os.path.join(lab_dir, "sandbox.yaml")
        if os.path.exists(qy_path):
            try:
                with open(qy_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                resources = data.get("environment", {}).get("resources", [])
                for res in resources:
                    for script_key in ("startup_script", "cleanup_script"):
                        sc = res.get(script_key)
                        if isinstance(sc, dict) and sc.get("path"):
                            d = os.path.normpath(os.path.join(lab_dir, sc.get("path")))
                            if os.path.isdir(d) and d not in tf_dirs:
                                if any(f.endswith(".tf") for f in os.listdir(d)):
                                    tf_dirs.append(d)
            except Exception:
                pass

        return tf_dirs

    def get_primary_tf_dir(self, lab_dir: str) -> str:
        """Returns the primary Terraform directory ('tf' or 'terraform') or first discovered."""
        tf_dir = os.path.join(lab_dir, "tf")
        if os.path.isdir(tf_dir):
            return tf_dir
        terraform_dir = os.path.join(lab_dir, "terraform")
        if os.path.isdir(terraform_dir):
            return terraform_dir
        all_dirs = self.find_tf_dirs(lab_dir)
        return all_dirs[0] if all_dirs else tf_dir

    def get_lab_exception(self, slug: str) -> Optional[Dict[str, Any]]:
        """Retrieves approved exception details for a lab if recorded in kb/exceptions.yaml."""
        for exc in self.exceptions_kb:
            if exc.get("slug") == slug:
                return exc
        return None

    def check_exception(self, lab_slug: str) -> Dict[str, Any]:
        """MCP Tool: Checks if a lab has an approved security exception."""
        slug = os.path.basename(lab_slug)
        exc = self.get_lab_exception(slug)
        if exc:
            return {
                "lab_slug": slug,
                "is_exempt": True,
                "exception": exc,
                "status": "APPROVED_EXCEPTION",
                "message": f"Lab has an approved exception: {exc.get('reason')} (Tracking: {exc.get('bug')})",
            }
        return {
            "lab_slug": slug,
            "is_exempt": False,
            "exception": None,
            "status": "NOT_EXEMPT",
            "message": "No approved exceptions on file. Standard security baseline applies.",
        }

    # -----------------------------------------------------------------------
    # Classification & Knowledge Retrieval
    # -----------------------------------------------------------------------

    def classify_lab(self, lab_dir_or_slug: str) -> Dict[str, Any]:
        """Classifies a lab directory against archetype definitions."""
        lab_dir = resolve_lab_dir(lab_dir_or_slug, self.lab_repo_root)
        slug = os.path.basename(lab_dir)

        # Collect lab files content across all TF harnesses
        tf_content = ""
        for d in self.find_tf_dirs(lab_dir):
            for root, _, files in os.walk(d):
                for f in files:
                    if f.endswith(".tf"):
                        try:
                            with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as tf_f:
                                tf_content += "\n" + tf_f.read()
                        except Exception:
                            pass

        lab_yaml_content = ""
        qy_path = os.path.join(lab_dir, "sandbox.yaml")
        if os.path.exists(qy_path):
            try:
                with open(qy_path, "r", encoding="utf-8", errors="ignore") as qf:
                    lab_yaml_content = qf.read()
            except Exception:
                pass

        instructions_content = ""
        inst_dir = os.path.join(lab_dir, "instructions")
        if os.path.exists(inst_dir):
            for root, _, files in os.walk(inst_dir):
                for f in files:
                    if f.endswith(".md"):
                        try:
                            with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as inf:
                                instructions_content += "\n" + inf.read()
                        except Exception:
                            pass

        assessments_content = ""
        ass_dir = os.path.join(lab_dir, "assessments")
        if os.path.exists(ass_dir):
            for root, _, files in os.walk(ass_dir):
                for f in files:
                    if f.endswith((".rb", ".py", ".sh")):
                        try:
                            with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as asf:
                                assessments_content += "\n" + asf.read()
                        except Exception:
                            pass

        matched_archetypes = []
        for arch in self.archetypes_kb:
            arch_id = arch.get("id")
            detect = arch.get("detect", {})
            any_rules = detect.get("any", [])
            matched = False
            reasons = []

            for rule in any_rules:
                if "tf_resource" in rule and rule["tf_resource"] in tf_content:
                    matched = True
                    reasons.append(f"Found Terraform resource '{rule['tf_resource']}'")
                elif "yaml_pattern" in rule and rule["yaml_pattern"] in lab_yaml_content:
                    matched = True
                    reasons.append(f"Found sandbox.yaml pattern '{rule['yaml_pattern']}'")
                elif "assessment_pattern" in rule and rule["assessment_pattern"] in assessments_content:
                    matched = True
                    reasons.append(f"Found assessment pattern '{rule['assessment_pattern']}'")
                elif "instruction_keyword" in rule and rule["instruction_keyword"].lower() in instructions_content.lower():
                    matched = True
                    reasons.append(f"Found instruction keyword '{rule['instruction_keyword']}'")
                elif "file_contains" in rule and (rule["file_contains"] in tf_content or rule["file_contains"] in lab_yaml_content):
                    matched = True
                    reasons.append(f"Found pattern '{rule['file_contains']}' in configs")

            if matched:
                matched_archetypes.append({
                    "id": arch_id,
                    "name": arch.get("name", arch_id),
                    "reasons": reasons,
                    "required_roles": arch.get("required_roles", []),
                    "nuances": arch.get("nuances", []),
                    "failure_mode": arch.get("failure_mode"),
                })

        return {
            "lab_slug": slug,
            "lab_dir": lab_dir,
            "matched_archetypes": matched_archetypes,
        }

    def recommend_iam_roles(self, lab_dir_or_slug: str) -> Dict[str, Any]:
        """Recommends minimal scoped IAM roles for a lab based on classification and KB."""
        classification = self.classify_lab(lab_dir_or_slug)
        lab_dir = classification["lab_dir"]
        slug = classification["lab_slug"]

        # Read current roles from sandbox.yaml
        current_roles = []
        has_owner = False
        has_editor = False
        has_dev_admin = False
        qy_path = os.path.join(lab_dir, "sandbox.yaml")
        if os.path.exists(qy_path):
            try:
                with open(qy_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    resources = data.get("environment", {}).get("resources", [])
                    for res in resources:
                        if res.get("type") == "gcp_user":
                            for perm in res.get("permissions", []):
                                for r in perm.get("roles", []):
                                    current_roles.append(r)
                                    if r == "roles/owner":
                                        has_owner = True
                                    elif r == "roles/editor":
                                        has_editor = True
                                    elif r == "roles/resourcemanager.projectIamAdmin":
                                        has_dev_admin = True
            except Exception as e:
                logger.warning(f"Error parsing sandbox.yaml for roles: {e}")

        # Baseline mandatory roles
        recommended_roles_map = {
            "roles/viewer": "Read-only access to GCP console navigation and resources without modification rights.",
            "roles/serviceusage.serviceUsageConsumer": "Required for CLI tools (gcloud, bq, cbt) to query service quota and status.",
        }

        # Roles from matched archetypes
        for arch in classification["matched_archetypes"]:
            for r_entry in arch.get("required_roles", []):
                r_id = r_entry.get("role")
                why = r_entry.get("why", "Required by archetype")
                if r_id:
                    recommended_roles_map[r_id] = why

        # Pitfalls that apply to this lab
        applicable_pitfalls = []
        arch_ids = {a["id"] for a in classification["matched_archetypes"]}
        for pit in self.pitfalls_kb:
            pit_id = pit.get("id")
            if pit_id in (
                "cloud-terminal-requires-editor",
                "cloud-terminal-backend-owner-override",
                "cloud-terminal-vpc-egress-bypass",
                "managed-ide-novmcreate-mig-bypass",
                "managed-ide-default-compute-sa-editor-theft",
                "managed-ide-authoritative-iam-launch-deadlock",
            ) and "cloud-terminal" in arch_ids:
                applicable_pitfalls.append(pit)
            elif pit_id == "custom-ide-iap-firewall-requirement" and "custom-web-ide" in arch_ids:
                applicable_pitfalls.append(pit)
            elif pit_id == "bigtable-ddl-requires-admin" and "bigtable-developer" in arch_ids:
                applicable_pitfalls.append(pit)
            elif pit_id == "ssh-assessment-silent-failure" and arch_ids.intersection({"sandbox-ssh-healthcheck", "sandbox-ssh-healthcheck"}):
                applicable_pitfalls.append(pit)
            elif pit_id == "sudo-requires-osadminlogin" and "compute-ssh-sudo" in arch_ids:
                applicable_pitfalls.append(pit)

        roles_to_remove = []
        if has_owner:
            roles_to_remove.append("roles/owner")
        if has_editor:
            roles_to_remove.append("roles/editor")
        if has_dev_admin:
            roles_to_remove.append("roles/resourcemanager.projectIamAdmin (MUST REMOVE BEFORE PROD PR)")

        return {
            "lab_slug": slug,
            "matched_archetypes": [a["name"] for a in classification["matched_archetypes"]],
            "current_roles": current_roles,
            "roles_to_remove": roles_to_remove,
            "recommended_roles": [
                {"role": r, "rationale": why} for r, why in recommended_roles_map.items()
            ],
            "applicable_pitfalls": applicable_pitfalls,
            "safeguards": [
                "Verify required GCP APIs remain pre-enabled in tf/api.tf or tf/main.tf.",
                "Ensure student assessment verification commands run successfully under scoped roles.",
                "Ensure roles/resourcemanager.projectIamAdmin is removed prior to production merge.",
            ],
        }

    def lookup_roles(
        self, archetype: Optional[str] = None, services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Provides role recommendations for greenfield lab design without requiring a local lab directory."""
        results = []
        if archetype:
            for arch in self.archetypes_kb:
                if archetype.lower() in arch.get("id", "").lower() or archetype.lower() in arch.get("name", "").lower():
                    results.append(arch)

        matching_roles = []
        if services:
            services_lower = [s.lower() for s in services]
            for r in self.roles_kb:
                r_id = r.get("id", "").lower()
                r_grants = r.get("grants", "").lower()
                if any(s in r_id or s in r_grants for s in services_lower):
                    matching_roles.append(r)

        return {
            "query_archetype": archetype,
            "query_services": services,
            "matching_archetypes": results,
            "matching_roles": matching_roles,
        }

    def explain_pitfall(
        self, topic: Optional[str] = None, lab_slug: Optional[str] = None
    ) -> Dict[str, Any]:
        """Explains specific security or platform pitfalls with symptoms and fixes."""
        matched = []
        if topic:
            t_low = topic.lower()
            for p in self.pitfalls_kb:
                if (
                    t_low in p.get("id", "").lower()
                    or t_low in p.get("symptom", "").lower()
                    or t_low in p.get("cause", "").lower()
                ):
                    matched.append(p)
        elif lab_slug:
            rec = self.recommend_iam_roles(lab_slug)
            matched = rec.get("applicable_pitfalls", [])
        else:
            matched = self.pitfalls_kb

        return {"pitfalls": matched}

    def record_pitfall(
        self,
        lab_slug: str,
        symptom: str,
        cause: str,
        fix: str,
        pitfall_id: Optional[str] = None,
        required_role: Optional[str] = None,
        resource_type: Optional[str] = None,
        service: Optional[str] = None,
        author: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a new pitfall into kb/pitfalls.yaml and refreshes the in-memory knowledge base."""
        slug = os.path.basename(lab_slug.strip().rstrip("/"))

        if pitfall_id:
            pid = re.sub(r"[^a-zA-Z0-9_\-]+", "-", pitfall_id.strip()).lower().strip("-")
        else:
            role_part = required_role.split("/")[-1].replace(".", "-") if required_role else "trap"
            pid = re.sub(r"[^a-zA-Z0-9_\-]+", "-", f"{slug}-{role_part}").lower().strip("-")

        # Check if pitfall with this ID already exists
        for p in self.pitfalls_kb:
            if p.get("id") == pid:
                return {
                    "status": "EXISTS",
                    "message": f"Pitfall with id '{pid}' already exists in knowledge base.",
                    "pitfall": p,
                }

        author_name = author or os.environ.get("USER", "tester")
        kb_file = os.path.join(self.kb_dir, "pitfalls.yaml")

        applies_when = {}
        if required_role:
            applies_when["role"] = required_role
        if resource_type:
            applies_when["resource_type"] = resource_type
        if service:
            applies_when["service"] = service

        block_lines = [
            f"  - id: {pid}",
        ]
        if applies_when:
            block_lines.append("    applies_when:")
            for k, v in applies_when.items():
                block_lines.append(f"      {k}: {v}")

        def clean_val(val: str) -> str:
            clean = val.replace('"', '\\"').replace("\n", " ").strip()
            return f'"{clean}"'

        block_lines.append(f"    symptom: {clean_val(symptom)}")
        block_lines.append(f"    cause: {clean_val(cause)}")
        block_lines.append(f"    fix: {clean_val(fix)}")
        block_lines.append(f"    provenance: {{ lab: {slug}, verified: true, author: {author_name} }}")

        entry_yaml = "\n".join(block_lines)

        try:
            if os.path.exists(kb_file):
                with open(kb_file, "r", encoding="utf-8") as f:
                    content = f.read()
                prefix = "" if content.endswith("\n") else "\n"
            else:
                prefix = "pitfalls:\n"

            with open(kb_file, "a", encoding="utf-8") as f:
                f.write(prefix + entry_yaml + "\n")
        except Exception as e:
            return {
                "status": "ERROR",
                "message": f"Failed to write to {kb_file}: {e}",
            }

        # Reload in-memory knowledge base
        self.pitfalls_kb = load_kb_yaml(kb_file).get("pitfalls", [])

        added = next((p for p in self.pitfalls_kb if p.get("id") == pid), None)

        return {
            "status": "RECORDED",
            "pitfall_id": pid,
            "kb_file": kb_file,
            "total_pitfalls": len(self.pitfalls_kb),
            "pitfall": added,
            "next_steps": [
                f"Review diff: git diff {kb_file}",
                f"Test retrieval: explain_pitfall(topic='{pid}')",
                f"Commit to git: git commit -m 'kb(pitfalls): record {pid} from {slug}'",
            ],
        }

    # -----------------------------------------------------------------------
    # Auditing & Pre-Merge Gate
    # -----------------------------------------------------------------------

    def audit_lab(self, lab_dir_or_slug: str) -> Dict[str, Any]:
        """Performs a comprehensive deterministic security and syntax audit of a lab."""
        lab_dir = resolve_lab_dir(lab_dir_or_slug, self.lab_repo_root)
        slug = os.path.basename(lab_dir)
        findings = []

        # 1. sandbox.yaml audit
        qy_path = os.path.join(lab_dir, "sandbox.yaml")
        lab_yaml_content = ""
        if not os.path.exists(qy_path):
            findings.append({
                "rule_id": "MISSING_SANDBOX_YAML",
                "severity": "CRITICAL",
                "file": "sandbox.yaml",
                "message": "sandbox.yaml configuration file not found.",
                "remediation": "Create standard sandbox.yaml manifest.",
            })
        else:
            try:
                with open(qy_path, "r", encoding="utf-8") as f:
                    lab_yaml_content = f.read()
                    data = yaml.safe_load(lab_yaml_content) or {}
                    resources = data.get("environment", {}).get("resources", [])
                    has_genai_sandbox_variant = any(
                        r.get("type") == "gcp_project"
                        and (r.get("policy_tier") == "genai_sandbox" or r.get("variant") == "genai_sandbox")
                        for r in resources
                    )
                    managed_ide_types = {"ide", "cloud_terminal", "looker_instance", "jupyter_notebook"}
                    for res in resources:
                        res_type = res.get("type")
                        res_id = res.get("id")
                        if res_type in managed_ide_types and has_genai_sandbox_variant:
                            findings.append({
                                "rule_id": "MANAGED_IDE_ON_GENAI_TIER",
                                "severity": "CRITICAL",
                                "file": "sandbox.yaml",
                                "message": (
                                    f"Managed Web IDE Proxy resource '{res_type}' ({res_id}) paired with 'policy_tier: genai_sandbox'. "
                                    "ide-provisioner@ is exempted from the genai_sandbox IAM Deny Policy (Policy-Deny-SA-Keys) and mounts "
                                    "static /home/user/keys.json in sandbox-platform-prod GKE, enabling full LLM key exfiltration (SEC-001)."
                                ),
                                "remediation": "Never pair Managed Web IDE Proxy (ide, cloud_terminal, looker_instance, jupyter_notebook) with policy_tier: genai_sandbox. Migrate to native Cloud Shell / GCE VM or revert variant to standard_sandbox.",
                            })
                        for perm in res.get("permissions", []):
                            roles = perm.get("roles", [])
                            if res_type == "gcp_user":
                                if "roles/owner" in roles:
                                    findings.append({
                                        "rule_id": "CRITICAL_ROLE_OWNER",
                                        "severity": "CRITICAL",
                                        "file": "sandbox.yaml",
                                        "message": f"Grants 'roles/owner' to user ({res_id}).",
                                        "remediation": "Replace with scoped minimal roles from recommend_iam_roles.",
                                    })
                                if "roles/editor" in roles:
                                    findings.append({
                                        "rule_id": "CRITICAL_ROLE_EDITOR",
                                        "severity": "CRITICAL",
                                        "file": "sandbox.yaml",
                                        "message": f"Grants 'roles/editor' to user ({res_id}).",
                                        "remediation": "Replace with scoped minimal roles from recommend_iam_roles.",
                                    })
                                if "roles/resourcemanager.projectIamAdmin" in roles:
                                    findings.append({
                                        "rule_id": "DEV_ADMIN_PRESENT",
                                        "severity": "CRITICAL",
                                        "file": "sandbox.yaml",
                                        "message": f"Temporary development permission 'roles/resourcemanager.projectIamAdmin' is present.",
                                        "remediation": "Remove before merging to production.",
                                    })
                                if "roles/iam.serviceAccountAdmin" in roles:
                                    findings.append({
                                        "rule_id": "PROJECT_LEVEL_SA_ADMIN",
                                        "severity": "CRITICAL",
                                        "file": "sandbox.yaml",
                                        "message": f"Grants 'roles/iam.serviceAccountAdmin' at project level to ({res_id}). Allows privilege escalation.",
                                        "remediation": "Scope in Terraform via google_service_account_iam_member on the specific service account.",
                                    })
                                if "roles/iam.serviceAccountUser" in roles:
                                    findings.append({
                                        "rule_id": "PROJECT_LEVEL_SA_USER",
                                        "severity": "WARNING",
                                        "file": "sandbox.yaml",
                                        "message": f"Grants 'roles/iam.serviceAccountUser' at project level to ({res_id}).",
                                        "remediation": "Consider scoping in Terraform on specific service account resource.",
                                    })
                            elif res_type == "cloud_terminal":
                                findings.append({
                                    "rule_id": "CLOUD_TERMINAL_SECURITY_GAP",
                                    "severity": "WARNING",
                                    "file": "sandbox.yaml",
                                    "message": (
                                        f"Uses 'cloud_terminal' ({res_id}): Schema v2 requires roles/editor in YAML, "
                                        "backend silently injects roles/owner + storage.admin + bigquery.admin (or static /home/user/keys.json), and the "
                                        "container runs outside project_0 VPC (bypassing secure_network.tf egress rules)."
                                    ),
                                    "remediation": (
                                        "Migrate to 'gcp_user' + native Cloud Shell if console access is acceptable. "
                                        "If cloud_terminal is required on non-LLM fleets (mini-lab), ensure all VMs in terraform-files/ "
                                        "are protected by secure_network.tf and IMDSv2."
                                    ),
                                })
                            elif res_type in ("ide", "looker_instance", "jupyter_notebook"):
                                findings.append({
                                    "rule_id": "MANAGED_IDE_STATIC_KEY_MOUNT",
                                    "severity": "WARNING",
                                    "file": "sandbox.yaml",
                                    "message": f"Uses Managed Web IDE Proxy resource '{res_type}' ({res_id}) which mounts a static JSON SA key at /home/user/keys.json via ide-provisioner@.",
                                    "remediation": "Ensure this lab is NOT on policy_tier: genai_sandbox and does not expose roles/aiplatform.user on the mounted key.",
                                })
                    if data.get("environment", {}).get("cloud_terminal") is True:
                        findings.append({
                            "rule_id": "MINILAB_CLOUD_TERMINAL_ENABLED",
                            "severity": "WARNING",
                            "file": "sandbox.yaml",
                            "message": (
                                "Mini-lab environment 'cloud_terminal: true' is enabled. Backend ignores custom YAML "
                                "roles and grants roles/owner, storage.admin, and bigquery.admin to the terminal session. "
                                "Additionally, direct terminal egress bypasses project_0 VPC firewalls."
                            ),
                            "remediation": (
                                "Lock down all GCE/GKE/Workbench VMs provisioned in terraform-files/ with secure_network.tf "
                                "and disable-legacy-endpoints='TRUE'. Do not use google_project_iam_policy to strip IDE-Provisioner."
                            ),
                        })
            except Exception as e:
                findings.append({
                    "rule_id": "YAML_PARSE_ERROR",
                    "severity": "CRITICAL",
                    "file": "sandbox.yaml",
                    "message": f"Failed to parse sandbox.yaml: {e}",
                    "remediation": "Fix YAML syntax formatting errors.",
                })

        # 2. Terraform audit across all harnesses (tf, terraform, cleanup, setup, teardown, terraform-files)
        tf_dirs = self.find_tf_dirs(lab_dir)
        has_egress = False

        if tf_dirs:
            for d in tf_dirs:
                # Gem 3: Check ephemeral cache and lockfile hygiene
                if os.path.exists(os.path.join(d, ".terraform")):
                    findings.append({
                        "rule_id": "EPHEMERAL_TERRAFORM_CACHE_PRESENT",
                        "severity": "WARNING",
                        "file": os.path.relpath(os.path.join(d, ".terraform"), lab_dir),
                        "message": "Ephemeral .terraform cache directory detected. Purge before staging commits.",
                        "remediation": "Run 'rm -rf .terraform' to avoid committing provider binaries.",
                    })
                if os.path.exists(os.path.join(d, ".terraform.lock.hcl")):
                    findings.append({
                        "rule_id": "EPHEMERAL_LOCKFILE_PRESENT",
                        "severity": "WARNING",
                        "file": os.path.relpath(os.path.join(d, ".terraform.lock.hcl"), lab_dir),
                        "message": "Ephemeral .terraform.lock.hcl lockfile detected. Purge before staging commits.",
                        "remediation": "Run 'rm -f .terraform.lock.hcl' to prevent cross-platform provider lock conflicts.",
                    })

                for root, _, files in os.walk(d):
                    for file in files:
                        if file.endswith(".tf"):
                            tf_path = os.path.join(root, file)
                            rel_path = os.path.relpath(tf_path, lab_dir)
                            try:
                                with open(tf_path, "r", encoding="utf-8", errors="ignore") as tff:
                                    tf_content = tff.read()
                                    if "roles/owner" in tf_content and (
                                        "google_project_iam_member" in tf_content
                                        or "google_project_iam_binding" in tf_content
                                    ):
                                        findings.append({
                                            "rule_id": "TF_ROLE_OWNER",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "message": "Grants 'roles/owner' via google_project_iam_member or binding.",
                                            "remediation": "Scope IAM permissions to minimal roles.",
                                        })
                                    if "google_project_iam_policy" in tf_content:
                                        if "roles/owner" in tf_content or "roles/editor" in tf_content:
                                            findings.append({
                                                "rule_id": "TF_DECEPTIVE_IAM_POLICY_OVERRIDE",
                                                "severity": "CRITICAL",
                                                "file": rel_path,
                                                "message": (
                                                    "Authoritative google_project_iam_policy overrides project IAM policy at "
                                                    "runtime and binds elevated roles (roles/owner or roles/editor), creating "
                                                    "deceptive least-privilege."
                                                ),
                                                "remediation": (
                                                    "Remove google_project_iam_policy and use additive google_project_iam_member "
                                                    "or google_service_account_iam_member."
                                                ),
                                            })
                                        if "ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com" not in tf_content:
                                            findings.append({
                                                "rule_id": "TF_AUTHORITATIVE_POLICY_OMITS_ORCHESTRATOR",
                                                "severity": "CRITICAL",
                                                "file": rel_path,
                                                "message": (
                                                    "Authoritative google_project_iam_policy overwrites all project IAM bindings "
                                                    "and omits ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com, which breaks "
                                                    "assessment grading and project teardown."
                                                ),
                                                "remediation": (
                                                    "Avoid google_project_iam_policy or explicitly bind roles/owner to "
                                                    "serviceAccount:ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com."
                                                ),
                                            })
                                    if (
                                        "google_project_iam_custom_role" in tf_content
                                        and "compute.instances.create" not in tf_content
                                        and (
                                            "compute.instanceGroupManagers.update" in tf_content
                                            or "compute.instanceGroupManagers.create" in tf_content
                                            or "compute.instanceGroups.update" in tf_content
                                        )
                                    ):
                                        findings.append({
                                            "rule_id": "TF_CUSTOM_ROLE_NOVMCREATE_MIG_BYPASS",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "message": (
                                                "Custom IAM role ('noVmCreate' pattern) omits compute.instances.create but grants "
                                                "compute.instanceGroupManagers.update/create. Students bypass this restriction by resizing "
                                                "the Managed Instance Group (gcloud compute instance-groups managed resize), causing "
                                                "the Google APIs Service Agent (@cloudservices.gserviceaccount.com) to provision VMs."
                                            ),
                                            "remediation": (
                                                "Do not rely on custom IAM method exclusions to block VM creation. Use hard project "
                                                "vCPU/GPU quotas and migrate from ManagedWebIDE cloud_terminal to standard gcp_user."
                                            ),
                                        })
                                    if (
                                        "-compute@developer.gserviceaccount.com" in tf_content
                                        and ("roles/editor" in tf_content or "roles/owner" in tf_content)
                                    ) or (
                                        "google_project_iam_custom_role" in tf_content
                                        and "google_compute_instance" in tf_content
                                        and "service_account" not in tf_content
                                    ):
                                        findings.append({
                                            "rule_id": "TF_DEFAULT_COMPUTE_SA_EDITOR_EXPOSURE",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "message": (
                                                "Binds roles/editor or roles/owner to the default Compute Engine service account "
                                                "(-compute@developer.gserviceaccount.com). Students can SSH into backend VMs via "
                                                "OS Login/IAP (or modify instance metadata) to steal a project-wide roles/editor "
                                                "OAuth2 token from http://169.254.169.254 and enable high-cost GenAI/Vertex APIs."
                                            ),
                                            "remediation": (
                                                "Never bind roles/editor to -compute@developer.gserviceaccount.com. Bind minimal "
                                                "logging/monitoring roles to the VM service account and enforce disable-legacy-endpoints='TRUE'."
                                            ),
                                        })
                                    if "roles/resourcemanager.projectIamAdmin" in tf_content or "roles/iam.securityAdmin" in tf_content:
                                        has_delegated_condition = (
                                            "modifiedGrantsByRole" in tf_content
                                            and ".hasOnly(" in tf_content
                                            and "roles/owner" not in tf_content
                                            and "roles/editor" not in tf_content
                                            and "roles/aiplatform.user" not in tf_content
                                        )
                                        has_deprivileged_default_sa = (
                                            "google_project_default_service_accounts" in tf_content
                                            and "DEPRIVILEGE" in tf_content
                                        )
                                        has_role_admin = (
                                            "roles/iam.roleAdmin" in tf_content
                                            or "roles/iam.roleAdmin" in lab_yaml_content
                                        )
                                        if has_role_admin and "modifiedGrantsByRole" in tf_content:
                                            findings.append({
                                                "rule_id": "IAM_ROLE_ADMIN_CUSTOM_ROLE_ESCALATION",
                                                "severity": "CRITICAL",
                                                "file": rel_path,
                                                "message": (
                                                    "Combines 'roles/iam.roleAdmin' with 'roles/resourcemanager.projectIamAdmin' "
                                                    "(or 'roles/iam.securityAdmin'). Even with a modifiedGrantsByRole condition allowing "
                                                    "a custom role ID, a student with roles/iam.roleAdmin can update that custom role "
                                                    "to include aiplatform.* / compute.* / storage.* permissions and grant it to themselves."
                                                ),
                                                "remediation": (
                                                    "Pre-create custom roles in Terraform, or restrict user_0 to predefined curriculum "
                                                    "roles in modifiedGrantsByRole.hasOnly([...]) without granting roles/iam.roleAdmin."
                                                ),
                                            })
                                        elif has_delegated_condition and has_deprivileged_default_sa:
                                            findings.append({
                                                "rule_id": "DELEGATED_IAM_ADMIN_CONDITION_VERIFIED",
                                                "severity": "INFO",
                                                "file": rel_path,
                                                "message": (
                                                    "Verified Delegated Role Grant condition (modifiedGrantsByRole.hasOnly) with "
                                                    "google_project_default_service_accounts (DEPRIVILEGE)."
                                                ),
                                                "remediation": "None required.",
                                            })
                                        else:
                                            findings.append({
                                                "rule_id": "TF_ROLE_IAM_ADMIN",
                                                "severity": "CRITICAL",
                                                "file": rel_path,
                                                "message": (
                                                    "Grants unconstrained 'roles/resourcemanager.projectIamAdmin' (or without "
                                                    "modifiedGrantsByRole.hasOnly + google_project_default_service_accounts DEPRIVILEGE) in Terraform."
                                                ),
                                                "remediation": (
                                                    "Remove projectIamAdmin role, or scope it via an IAM Condition using "
                                                    "api.getAttribute('iam.googleapis.com/modifiedGrantsByRole', []).hasOnly([...]) "
                                                    "plus google_project_default_service_accounts (action = 'DEPRIVILEGE')."
                                                ),
                                            })
                                    if "google_service_account_key" in tf_content and (
                                        "policy_tier: genai_sandbox" in lab_yaml_content
                                        or "roles/aiplatform.user" in tf_content
                                        or "roles/editor" in tf_content
                                        or "roles/owner" in tf_content
                                    ):
                                        findings.append({
                                            "rule_id": "SA_KEY_WITH_LLM_OR_BROAD_ROLE",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "message": (
                                                "Mints a static 'google_service_account_key' in a genai_sandbox lab or alongside "
                                                "roles/aiplatform.user / roles/editor / roles/owner. VPC egress (secure_network.tf) "
                                                "cannot block Control-Plane API abuse once a JSON key is copied out of the browser (SEC-001)."
                                            ),
                                            "remediation": "Use a VM-attached google_service_account with disable-legacy-endpoints=TRUE instead of google_service_account_key, or strictly scope the SA to non-LLM roles with an IAM expiry condition.",
                                        })
                                    if "serviceAccount:serviceAccount:" in tf_content or "serviceAccount:${module." in tf_content:
                                        findings.append({
                                            "rule_id": "TF_DUPLICATE_SA_PREFIX",
                                            "severity": "CRITICAL",
                                            "file": rel_path,
                                            "message": "Duplicated 'serviceAccount:' prefix in IAM binding.",
                                            "remediation": "Remove duplicate 'serviceAccount:' prefix.",
                                        })
                                    if "deny-all-egress" in tf_content or "secure_network" in file:
                                        has_egress = True
                            except Exception as e:
                                logger.warning(f"Failed to read TF file {tf_path}: {e}")

            # Check for mandatory runtime.yaml across all Terraform harnesses (SEC-004)
            for d in sorted(tf_dirs):
                runtime_yaml_path = os.path.join(d, "runtime.yaml")
                rel_runtime_path = os.path.relpath(runtime_yaml_path, lab_dir)
                rel_d = os.path.relpath(d, lab_dir)
                if not os.path.exists(runtime_yaml_path):
                    findings.append({
                        "rule_id": "MISSING_RUNTIME_YAML",
                        "severity": "CRITICAL",
                        "file": rel_runtime_path,
                        "message": (
                            f"Missing 'runtime.yaml' in Terraform directory '{rel_d}'. "
                            "The Cloud Sandbox Platform script runner requires runtime.yaml declaring 'runtime: terraform' and 'version: 1.12.1'. "
                            "Omitting it causes lab launch to fail immediately with 'bad request, invalid script: missing runtime.yaml file' (SEC-004)."
                        ),
                        "remediation": "Create runtime.yaml declaring 'runtime: terraform' and 'version: 1.12.1'.",
                    })
                else:
                    try:
                        with open(runtime_yaml_path, "r", encoding="utf-8") as rf:
                            rdata = yaml.safe_load(rf) or {}
                            if rdata.get("runtime") != "terraform":
                                findings.append({
                                    "rule_id": "INVALID_RUNTIME_YAML",
                                    "severity": "CRITICAL",
                                    "file": rel_runtime_path,
                                    "message": (
                                        f"Invalid runtime declared in '{rel_runtime_path}': "
                                        f"expected 'runtime: terraform', found '{rdata.get('runtime')}'. (SEC-004)"
                                    ),
                                    "remediation": "Set 'runtime: terraform' and 'version: 1.12.1' in runtime.yaml.",
                                })
                    except Exception as e:
                        findings.append({
                            "rule_id": "INVALID_RUNTIME_YAML",
                            "severity": "CRITICAL",
                            "file": rel_runtime_path,
                            "message": f"Failed to parse '{rel_runtime_path}': {e} (SEC-004)",
                            "remediation": "Fix syntax error in runtime.yaml.",
                        })

            if not has_egress:
                findings.append({
                    "rule_id": "MISSING_EGRESS_FIREWALL",
                    "severity": "WARNING",
                    "file": "tf/secure_network.tf",
                    "message": "No network egress restrictions found (secure_network.tf missing).",
                    "remediation": "Apply egress_firewall patch to block unauthorized egress ports.",
                })
        else:
            findings.append({
                "rule_id": "MISSING_TF_DIR",
                "severity": "INFO",
                "file": "tf/",
                "message": "No Terraform directory found for lab.",
                "remediation": "Ensure lab infrastructure is provisioned as expected.",
            })

        # Check sandbox.yaml startup_script/cleanup_script if referencing a directory missing runtime.yaml
        if os.path.exists(qy_path):
            try:
                with open(qy_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                resources = data.get("environment", {}).get("resources", [])
                for res in resources:
                    for script_key in ("startup_script", "cleanup_script"):
                        sc = res.get(script_key)
                        if isinstance(sc, dict) and sc.get("path"):
                            sp = sc.get("path")
                            abs_sp = os.path.normpath(os.path.join(lab_dir, sp))
                            if os.path.isdir(abs_sp) and abs_sp not in tf_dirs:
                                r_yaml = os.path.join(abs_sp, "runtime.yaml")
                                if not os.path.exists(r_yaml) and sc.get("type") in ("terraform", "sandbox-platform"):
                                    findings.append({
                                        "rule_id": "MISSING_RUNTIME_YAML",
                                        "severity": "CRITICAL",
                                        "file": os.path.relpath(r_yaml, lab_dir),
                                        "message": (
                                            f"Missing 'runtime.yaml' in '{os.path.relpath(abs_sp, lab_dir)}' wired to {script_key}. "
                                            "The Cloud Sandbox Platform script runner requires runtime.yaml declaring 'runtime: terraform' and 'version: 1.12.1' "
                                            "(SEC-004)."
                                        ),
                                        "remediation": "Create runtime.yaml declaring 'runtime: terraform' and 'version: 1.12.1'.",
                                    })
            except Exception:
                pass

        # 3. Assessments audit
        ass_dir = os.path.join(lab_dir, "assessments")
        if os.path.exists(ass_dir):
            for root, _, files in os.walk(ass_dir):
                for file in files:
                    if file.endswith((".rb", ".sh", ".py")):
                        f_path = os.path.join(root, file)
                        rel_path = os.path.relpath(f_path, lab_dir)
                        try:
                            with open(f_path, "r", encoding="utf-8", errors="ignore") as af:
                                content = af.read()
                                if "history.sqlite" in content and "grep" in content and "2>&1" not in content:
                                    findings.append({
                                        "rule_id": "ASSESSMENT_GREP_STDERR",
                                        "severity": "WARNING",
                                        "file": rel_path,
                                        "message": "Queries history.sqlite with grep without '2>&1' stderr redirection.",
                                        "remediation": "Append '2>&1' to prevent stderr from breaking assessment exit code.",
                                    })
                        except Exception:
                            pass

        # 4. Instructions audit
        inst_dir = os.path.join(lab_dir, "instructions")
        if os.path.exists(inst_dir):
            for root, _, files in os.walk(inst_dir):
                for file in files:
                    if file.endswith(".md"):
                        f_path = os.path.join(root, file)
                        rel_path = os.path.relpath(f_path, lab_dir)
                        try:
                            with open(f_path, "r", encoding="utf-8", errors="ignore") as inf:
                                content = inf.read()
                                if ".svc.id.goog[" in content:
                                    findings.append({
                                        "rule_id": "LEGACY_WORKLOAD_IDENTITY",
                                        "severity": "WARNING",
                                        "file": rel_path,
                                        "message": "Uses legacy Workload Identity principal format instead of principal://iam.googleapis.com/...",
                                        "remediation": "Update principal format to modern direct principal syntax.",
                                    })
                                if "{{{project_0.project_number}}}" in content:
                                    findings.append({
                                        "rule_id": "BLANK_PROJECT_NUMBER_TAG",
                                        "severity": "WARNING",
                                        "file": rel_path,
                                        "message": "Uses {{{project_0.project_number}}} template tag, which resolves to blank in student environments.",
                                        "remediation": "Fetch dynamically: $(gcloud projects describe {{{project_0.project_id}}} --format='get(projectNumber)').",
                                    })
                                if re.search(r'\{\{\{[^}]+\|\s*[^}]+\}\}\}', content):
                                    findings.append({
                                        "rule_id": "MUSTACHE_PIPE_SYNTAX",
                                        "severity": "INFO",
                                        "file": rel_path,
                                        "message": "Pipe/fallback syntax in mustache tag (e.g. '{{{tag | fallback}}}').",
                                        "remediation": "Optional: remove pipe fallback if not using Cloud Sandbox Platform default syntax.",
                                    })
                                if re.search(r'<code>[^<\n]*\{\{\{[^}\n]+\}\}\}[^<\n]*</code>', content):
                                    findings.append({
                                        "rule_id": "MUSTACHE_IN_HTML_CODE",
                                        "severity": "INFO",
                                        "file": rel_path,
                                        "message": "Mustache tags inside raw HTML <code> tags.",
                                        "remediation": "Optional: use <ql-code-block ... templated> if dynamic expansion is needed.",
                                    })
                                if re.search(r'`[^`\n]*\{\{\{[^}\n]+\}\}\}[^`\n]*`', content):
                                    findings.append({
                                        "rule_id": "MUSTACHE_IN_BACKTICKS",
                                        "severity": "INFO",
                                        "file": rel_path,
                                        "message": "Mustache tags inside inline markdown backticks.",
                                        "remediation": "Optional: use <ql-code-block ... templated> if dynamic expansion is needed.",
                                    })
                                for m in re.finditer(r'<ql-code-block([^>]*)>(.*?)</ql-code-block>', content, re.DOTALL):
                                    attrs, code = m.group(1), m.group(2)
                                    if "{{{" in code and "templated" not in attrs:
                                        findings.append({
                                            "rule_id": "QL_CODE_BLOCK_NOT_TEMPLATED",
                                            "severity": "INFO",
                                            "file": rel_path,
                                            "message": "<ql-code-block> contains mustache template tags but lacks 'templated' attribute.",
                                            "remediation": "Add 'templated' attribute to <ql-code-block> tag.",
                                        })
                        except Exception:
                            pass

        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        warning_count = sum(1 for f in findings if f["severity"] == "WARNING")
        info_count = sum(1 for f in findings if f["severity"] == "INFO")

        exc = self.get_lab_exception(slug)
        tf_dirs_rel = [os.path.relpath(d, lab_dir) for d in tf_dirs]
        is_pure_saas = len(tf_dirs) == 0 and "compute" not in lab_yaml_content.lower()

        return {
            "lab_slug": slug,
            "lab_dir": lab_dir,
            "exception": exc,
            "is_exempt": exc is not None,
            "tf_directories": tf_dirs_rel,
            "is_pure_saas_or_cloud_shell": is_pure_saas,
            "total_findings": len(findings),
            "summary": {
                "critical": critical_count,
                "warning": warning_count,
                "info": info_count,
            },
            "findings": findings,
        }

    def validate_pre_merge(self, lab_dir_or_slug: str) -> Dict[str, Any]:
        """PASS/FAIL pre-merge gate enforcing security baseline compliance."""
        audit_res = self.audit_lab(lab_dir_or_slug)
        slug = audit_res["lab_slug"]
        exc = audit_res.get("exception")

        violations = [
            f for f in audit_res["findings"] if f["severity"] == "CRITICAL"
        ]

        # Egress is also mandatory for PASS
        egress_missing = [
            f for f in audit_res["findings"] if f["rule_id"] == "MISSING_EGRESS_FIREWALL"
        ]
        if egress_missing:
            violations.extend(egress_missing)

        # Gem 1: Honor approved exceptions if on file in kb/exceptions.yaml
        if exc:
            exc_type = exc.get("type")
            exempted_violations = []
            unexempted_violations = []
            for v in violations:
                # If intentional vulnerability, exempt IAM role findings
                if exc_type == "intentional_vulnerability" and ("ROLE" in v.get("rule_id", "") or "DEV_ADMIN" in v.get("rule_id", "")):
                    exempted_violations.append(v)
                # If third party egress, exempt missing egress firewall
                elif exc_type == "third_party_egress" and v.get("rule_id") == "MISSING_EGRESS_FIREWALL":
                    exempted_violations.append(v)
                else:
                    unexempted_violations.append(v)

            if not unexempted_violations:
                return {
                    "lab_slug": slug,
                    "status": "PASS_WITH_EXCEPTION",
                    "is_exempt": True,
                    "exception": exc,
                    "exempted_violations_count": len(exempted_violations),
                    "blocking_violations_count": 0,
                    "blocking_violations": [],
                    "summary": f"Lab PASSED pre-merge gate under approved exception '{exc_type}': {exc.get('reason')} (Tracking: {exc.get('bug')})",
                }
            violations = unexempted_violations

        status = "PASS" if not violations else "FAIL"
        return {
            "lab_slug": slug,
            "status": status,
            "is_exempt": exc is not None,
            "exception": exc,
            "blocking_violations_count": len(violations),
            "blocking_violations": violations,
            "summary": (
                "Lab PASSED all pre-merge hardening verification gates. Ready for PR!"
                if status == "PASS"
                else f"Lab FAILED pre-merge validation with {len(violations)} blocking violations."
            ),
        }

    # -----------------------------------------------------------------------
    # Dynamic Fleet & Backlog Scanning (Zero Static CSV)
    # -----------------------------------------------------------------------

    def get_fleet_status(
        self, repo_path: Optional[str] = None, filter_status: Optional[str] = None
    ) -> Dict[str, Any]:
        """Dynamically scans repository catalog to evaluate fleet-wide hardening status."""
        default_sub = "sandboxes" if os.path.isdir(os.path.join(self.lab_repo_root, "sandboxes")) else "labs"
        root = repo_path or os.path.join(self.lab_repo_root, default_sub)
        if not os.path.isdir(root):
            return {"error": f"Catalog path '{root}' does not exist"}

        lab_dirs = [
            os.path.join(root, d)
            for d in sorted(os.listdir(root))
            if os.path.isdir(os.path.join(root, d))
        ]

        total = len(lab_dirs)
        hardened = []
        partial = []
        untouched = []

        for l_dir in lab_dirs:
            slug = os.path.basename(l_dir)
            qy_path = os.path.join(l_dir, "sandbox.yaml")
            tf_dir = os.path.join(l_dir, "tf")
            if not os.path.exists(tf_dir):
                tf_dir = os.path.join(l_dir, "terraform")

            has_owner_editor = False
            has_dev_admin = False
            has_egress = False

            if os.path.exists(qy_path):
                try:
                    with open(qy_path, "r", encoding="utf-8", errors="ignore") as f:
                        q_text = f.read()
                        if "roles/owner" in q_text or "roles/editor" in q_text:
                            has_owner_editor = True
                        if "roles/resourcemanager.projectIamAdmin" in q_text:
                            has_dev_admin = True
                except Exception:
                    pass

            if os.path.exists(tf_dir):
                if os.path.exists(os.path.join(tf_dir, "secure_network.tf")):
                    has_egress = True

            if not has_owner_editor and has_egress and not has_dev_admin:
                hardened.append(slug)
            elif has_egress or not has_owner_editor:
                partial.append(slug)
            else:
                untouched.append(slug)

        summary = {
            "total_catalog_labs": total,
            "hardened_count": len(hardened),
            "partial_count": len(partial),
            "untouched_count": len(untouched),
            "hardened_percent": round((len(hardened) / total * 100), 2) if total else 0,
        }

        if filter_status == "hardened":
            summary["labs"] = hardened
        elif filter_status == "partial":
            summary["labs"] = partial
        elif filter_status == "untouched":
            summary["labs"] = untouched

        return summary

    def get_backlog(
        self, repo_path: Optional[str] = None, limit: int = 10
    ) -> Dict[str, Any]:
        """Dynamically identifies and scores high-risk unhardened sandboxes for prioritized remediation."""
        default_sub = "sandboxes" if os.path.isdir(os.path.join(self.lab_repo_root, "sandboxes")) else "labs"
        root = repo_path or os.path.join(self.lab_repo_root, default_sub)
        if not os.path.isdir(root):
            return {"error": f"Catalog path '{root}' does not exist"}

        lab_dirs = [
            os.path.join(root, d)
            for d in os.listdir(root)
            if os.path.isdir(os.path.join(root, d))
        ]

        scored_labs = []

        for l_dir in lab_dirs:
            slug = os.path.basename(l_dir)
            # Gem 1: Skip labs with approved exceptions
            if self.get_lab_exception(slug):
                continue

            qy_path = os.path.join(l_dir, "sandbox.yaml")
            tf_dirs = self.find_tf_dirs(l_dir)

            risk_score = 0
            risk_factors = []

            # Check sandbox.yaml
            if os.path.exists(qy_path):
                try:
                    with open(qy_path, "r", encoding="utf-8", errors="ignore") as f:
                        q_text = f.read()
                        if "roles/owner" in q_text:
                            risk_score += 10
                            risk_factors.append("roles/owner granted to student")
                        if "roles/editor" in q_text:
                            risk_score += 8
                            risk_factors.append("roles/editor granted to student")
                        if "roles/iam.serviceAccountAdmin" in q_text:
                            risk_score += 8
                            risk_factors.append("roles/iam.serviceAccountAdmin at project level")
                        if "type: cloud_terminal" in q_text:
                            risk_score += 6
                            risk_factors.append("deprecated cloud_terminal resource")
                except Exception:
                    pass
            else:
                risk_score += 4
                risk_factors.append("missing sandbox.yaml")

            # Check network egress across all harnesses
            if tf_dirs:
                has_egress = any(os.path.exists(os.path.join(d, "secure_network.tf")) for d in tf_dirs)
                if not has_egress:
                    risk_score += 5
                    risk_factors.append("missing egress firewall (secure_network.tf)")
            else:
                risk_score += 2
                risk_factors.append("no Terraform directory")

            if risk_score > 0:
                scored_labs.append({
                    "slug": slug,
                    "risk_score": risk_score,
                    "risk_factors": risk_factors,
                    "lab_dir": l_dir,
                })

        # Sort descending by risk score
        scored_labs.sort(key=lambda x: x["risk_score"], reverse=True)
        top_backlog = scored_labs[:limit]

        return {
            "total_unhardened_labs": len(scored_labs),
            "showing_top": len(top_backlog),
            "backlog": top_backlog,
        }

    # -----------------------------------------------------------------------
    # Remediation / Write Tool Implementation
    # -----------------------------------------------------------------------

    def apply_security_patch(
        self, lab_dir_or_slug: str, patch_type: str, dry_run: bool = True
    ) -> Dict[str, Any]:
        """Applies or previews security remediation patches on a lab."""
        lab_dir = resolve_lab_dir(lab_dir_or_slug, self.lab_repo_root)
        slug = os.path.basename(lab_dir)

        diffs = []
        affected_files = []

        tf_dir = self.get_primary_tf_dir(lab_dir)

        if patch_type == "egress_firewall":
            target_file = os.path.join(tf_dir, "secure_network.tf")
            template_file = os.path.join(self.assets_dir, "secure_network.tf.template")

            if not os.path.exists(template_file):
                return {"error": f"Template not found at {template_file}"}

            with open(template_file, "r", encoding="utf-8") as f:
                new_content = f.read()

            old_content = ""
            if os.path.exists(target_file):
                with open(target_file, "r", encoding="utf-8") as f:
                    old_content = f.read()

            diff = "".join(
                difflib.unified_diff(
                    old_content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{os.path.relpath(target_file, lab_dir)}",
                    tofile=f"b/{os.path.relpath(target_file, lab_dir)}",
                )
            )
            diffs.append({"file": os.path.relpath(target_file, lab_dir), "diff": diff})
            affected_files.append(target_file)

            if not dry_run:
                os.makedirs(tf_dir, exist_ok=True)
                with open(target_file, "w", encoding="utf-8") as f:
                    f.write(new_content)

            # Ensure runtime.yaml exists in tf_dir so script runner does not fail at launch (SEC-004)
            runtime_target = os.path.join(tf_dir, "runtime.yaml")
            runtime_template = os.path.join(self.assets_dir, "runtime.yaml.template")
            if os.path.exists(runtime_template) and not os.path.exists(runtime_target):
                with open(runtime_template, "r", encoding="utf-8") as rf:
                    rt_content = rf.read()
                rt_diff = "".join(
                    difflib.unified_diff(
                        "".splitlines(keepends=True),
                        rt_content.splitlines(keepends=True),
                        fromfile=f"a/{os.path.relpath(runtime_target, lab_dir)}",
                        tofile=f"b/{os.path.relpath(runtime_target, lab_dir)}",
                    )
                )
                diffs.append({"file": os.path.relpath(runtime_target, lab_dir), "diff": rt_diff})
                affected_files.append(runtime_target)
                if not dry_run:
                    os.makedirs(tf_dir, exist_ok=True)
                    with open(runtime_target, "w", encoding="utf-8") as wf:
                        wf.write(rt_content)

        elif patch_type == "disable_imds_v1":
            # Search for compute instance resources across all .tf harnesses
            for d in self.find_tf_dirs(lab_dir):
                for root, _, files in os.walk(d):
                    for file in files:
                        if file.endswith(".tf"):
                            tf_file = os.path.join(root, file)
                            with open(tf_file, "r", encoding="utf-8") as f:
                                orig = f.read()

                            if "resource \"google_compute_instance\"" in orig:
                                if "disable-legacy-endpoints" not in orig:
                                    # Inject metadata block
                                    replacement = (
                                        "  metadata = {\n"
                                        "    disable-legacy-endpoints = \"TRUE\"\n"
                                        "  }\n"
                                    )
                                    # Insert after machine_type or at start of resource
                                    pattern = r'(resource\s+"google_compute_instance"\s+"[^"]+"\s*\{[^\}]*?machine_type\s*=\s*[^\n]+)'
                                    if re.search(pattern, orig, re.DOTALL):
                                        modified = re.sub(pattern, r'\1\n' + replacement, orig, count=1)
                                        diff = "".join(
                                            difflib.unified_diff(
                                                orig.splitlines(keepends=True),
                                                modified.splitlines(keepends=True),
                                                fromfile=f"a/{os.path.relpath(tf_file, lab_dir)}",
                                                tofile=f"b/{os.path.relpath(tf_file, lab_dir)}",
                                            )
                                        )
                                        diffs.append({"file": os.path.relpath(tf_file, lab_dir), "diff": diff})
                                        affected_files.append(tf_file)
                                        if not dry_run:
                                            with open(tf_file, "w", encoding="utf-8") as wf:
                                                wf.write(modified)

        elif patch_type == "minimize_iam_roles":
            # Update sandbox.yaml to swap roles/owner and roles/editor with recommended roles
            qy_path = os.path.join(lab_dir, "sandbox.yaml")
            if os.path.exists(qy_path):
                with open(qy_path, "r", encoding="utf-8") as f:
                    orig = f.read()

                rec = self.recommend_iam_roles(lab_dir)
                rec_roles = [r["role"] for r in rec.get("recommended_roles", [])]

                try:
                    data = yaml.safe_load(orig)
                    resources = data.get("environment", {}).get("resources", [])
                    modified_yaml = False
                    for res in resources:
                        if res.get("type") == "gcp_user":
                            for perm in res.get("permissions", []):
                                current = perm.get("roles", [])
                                filtered = [
                                    r for r in current
                                    if r not in ("roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin")
                                ]
                                for r in rec_roles:
                                    if r not in filtered:
                                        filtered.append(r)
                                perm["roles"] = filtered
                                modified_yaml = True

                    if modified_yaml:
                        new_content = yaml.dump(data, sort_keys=False)
                        diff = "".join(
                            difflib.unified_diff(
                                orig.splitlines(keepends=True),
                                new_content.splitlines(keepends=True),
                                fromfile=f"a/{os.path.relpath(qy_path, lab_dir)}",
                                tofile=f"b/{os.path.relpath(qy_path, lab_dir)}",
                            )
                        )
                        diffs.append({"file": os.path.relpath(qy_path, lab_dir), "diff": diff})
                        affected_files.append(qy_path)
                        if not dry_run:
                            with open(qy_path, "w", encoding="utf-8") as wf:
                                wf.write(new_content)
                except Exception as e:
                    return {"error": f"Failed to rewrite sandbox.yaml: {e}"}

        elif patch_type == "fix_mustache":
            # Fix mustache in backticks or code blocks in instructions/*.md
            inst_dir = os.path.join(lab_dir, "instructions")
            if os.path.exists(inst_dir):
                for root, _, files in os.walk(inst_dir):
                    for file in files:
                        if file.endswith(".md"):
                            md_file = os.path.join(root, file)
                            with open(md_file, "r", encoding="utf-8") as f:
                                orig = f.read()

                            # Replace `{{{...}}}` with <ql-code-block templated>{{{...}}}</ql-code-block>
                            modified = re.sub(
                                r'`([^`\n]*\{\{\{[^}\n]+\}\}\}[^`\n]*)`',
                                r'<ql-code-block templated>\1</ql-code-block>',
                                orig,
                            )
                            # Replace <code>{{{...}}}</code> with <ql-code-block templated>{{{...}}}</ql-code-block>
                            modified = re.sub(
                                r'<code>([^<\n]*\{\{\{[^}\n]+\}\}\}[^<\n]*)</code>',
                                r'<ql-code-block templated>\1</ql-code-block>',
                                modified,
                            )

                            if modified != orig:
                                diff = "".join(
                                    difflib.unified_diff(
                                        orig.splitlines(keepends=True),
                                        modified.splitlines(keepends=True),
                                        fromfile=f"a/{os.path.relpath(md_file, lab_dir)}",
                                        tofile=f"b/{os.path.relpath(md_file, lab_dir)}",
                                    )
                                )
                                diffs.append({"file": os.path.relpath(md_file, lab_dir), "diff": diff})
                                affected_files.append(md_file)
                                if not dry_run:
                                    with open(md_file, "w", encoding="utf-8") as wf:
                                        wf.write(modified)

        elif patch_type == "runtime_yaml":
            template_file = os.path.join(self.assets_dir, "runtime.yaml.template")
            if not os.path.exists(template_file):
                return {"error": f"Template not found at {template_file}"}

            with open(template_file, "r", encoding="utf-8") as f:
                rt_content = f.read()

            target_dirs = self.find_tf_dirs(lab_dir)
            if not target_dirs:
                target_dirs = [self.get_primary_tf_dir(lab_dir)]

            for d in target_dirs:
                runtime_target = os.path.join(d, "runtime.yaml")
                old_content = ""
                if os.path.exists(runtime_target):
                    with open(runtime_target, "r", encoding="utf-8") as f:
                        old_content = f.read()

                if old_content != rt_content:
                    diff = "".join(
                        difflib.unified_diff(
                            old_content.splitlines(keepends=True),
                            rt_content.splitlines(keepends=True),
                            fromfile=f"a/{os.path.relpath(runtime_target, lab_dir)}",
                            tofile=f"b/{os.path.relpath(runtime_target, lab_dir)}",
                        )
                    )
                    diffs.append({"file": os.path.relpath(runtime_target, lab_dir), "diff": diff})
                    affected_files.append(runtime_target)
                    if not dry_run:
                        os.makedirs(d, exist_ok=True)
                        with open(runtime_target, "w", encoding="utf-8") as wf:
                            wf.write(rt_content)
        else:
            return {"error": f"Unsupported patch_type '{patch_type}'"}

        return {
            "lab_slug": slug,
            "patch_type": patch_type,
            "dry_run": dry_run,
            "affected_files": affected_files,
            "diffs": diffs,
            "status": "dry-run preview complete" if dry_run else "patch applied successfully",
        }
