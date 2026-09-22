#!/usr/bin/env python3
"""
Batch Migration CLI for GCP LLM Fleet Variant.

Iterates through target GenAI labs in cloud-sandboxes:
1. Validates absence of manual SA key creation.
2. Updates sandbox.yaml to `policy_tier: genai_sandbox`.
3. Creates a dedicated GitHub Issues tracking ticket linked under parent SEC-102.
4. Opens a formatted pull request on GitHub tagged `gcp-llm-fleet-rollout`.
5. Updates the master inventory tracking CSV.

Usage:
  python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/batch_migrate_genai_fleet.py --slugs gml006-analyze-images-gemini sandbox-demo-multimodality-with-gemini
  python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/batch_migrate_genai_fleet.py --all --limit 5
  python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/batch_migrate_genai_fleet.py --dry-run
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import yaml

PARENT_BUG_ID = "SEC-102"
BUG_COMPONENT_ID = "1939024"  # Lab Architects project component
ASSIGNEE_LDAP = f"{os.environ.get('USER', 'znoah')}@google.com"
CAMPAIGN_TAG = "gcp-llm-fleet-rollout"


def run_cmd(cmd, cwd=None, check=True):
    """Execute a shell command safely and return stdout."""
    res = subprocess.run(
        cmd,
        cwd=cwd,
        shell=isinstance(cmd, str),
        capture_output=True,
        text=True
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}\nStdout: {res.stdout}")
    return res


def create_gh issue_ticket(slug, parent_id=PARENT_BUG_ID, assignee=ASSIGNEE_LDAP):
    """Create a child GitHub Issues issue linked to the parent rollout ticket."""
    title = f"[Fleet Migration] Migrate {slug} to genai_sandbox variant"
    desc = (
        f"Migrate `{slug}` to the `genai_sandbox` fleet variant in `sandbox.yaml`.\n\n"
        f"* **Parent Initiative**: http://b/{parent_id}\n"
        f"* **Repository**: example-org/cloud-sandboxes\n"
        f"* **Rollout Campaign**: `{CAMPAIGN_TAG}`\n"
    )

    issues_bin = "/google/bin/releases/issues-cli/issues"
    if not os.path.exists(issues_bin):
        issues_bin = "issues"

    try:
        cmd = [
            issues_bin, "mutate", "create",
            f"--component_id={BUG_COMPONENT_ID}",
            f"--title={title}",
            f"--description={desc}",
            "--priority=P3",
            "--severity=S3",
            "--type=TASK",
            f"--assignee={assignee}",
            "--status=ASSIGNED"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            match = re.search(r"\b(\d{8,10})\b", res.stdout)
            if match:
                child_id = match.group(1)
                # Link parent
                subprocess.run(
                    [issues_bin, "mutate", "update", "add-children", f"--issue_id={parent_id}", f"--child_ids={child_id}"],
                    capture_output=True,
                    text=True,
                )
                return child_id
    except Exception as e:
        print(f"Warning: Failed to create gh issue ticket for {slug}: {e}")

    return None


def migrate_lab_yaml(lab_path):
    """Update policy_tier: genai_sandbox in sandbox.yaml preserving comments and formatting."""
    ql_yaml_path = os.path.join(lab_path, "sandbox.yaml")
    if not os.path.exists(ql_yaml_path):
        return False, "sandbox.yaml not found"

    with open(ql_yaml_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify YAML is valid
    try:
        data = yaml.safe_load(content)
    except Exception as e:
        return False, f"Invalid YAML: {e}"

    # Check if already genai_sandbox
    resources = data.get("environment", {}).get("resources", [])
    projects = [r for r in resources if isinstance(r, dict) and r.get("type") == "gcp_project"]
    if not projects:
        return False, "No gcp_project found in environment.resources"

    all_llm = all(p.get("variant") == "genai_sandbox" for p in projects)
    if all_llm:
        return True, "Already compliant (policy_tier: genai_sandbox)"

    # Replace variant: standard_sandbox -> policy_tier: genai_sandbox or inject policy_tier: genai_sandbox
    has_variant_key = False
    lines = content.splitlines()
    in_gcp_proj_check = False
    for line in lines:
        if re.search(r"-\s+type:\s+gcp_project\b", line):
            in_gcp_proj_check = True
        elif in_gcp_proj_check and re.search(r"^\s+variant:\s+", line):
            has_variant_key = True
            break
        elif in_gcp_proj_check and re.search(r"^\s+-\s+type:\s+|^\s*student_visible_outputs:", line):
            break

    new_lines = []
    in_gcp_project = False
    injected = False

    for line in lines:
        if re.search(r"-\s+type:\s+gcp_project\b", line):
            in_gcp_project = True
            injected = False
            new_lines.append(line)
        elif in_gcp_project and has_variant_key and re.search(r"^\s+variant:\s+", line):
            indent = len(line) - len(line.lstrip())
            new_lines.append(f"{' ' * indent}policy_tier: genai_sandbox")
            in_gcp_project = False
        elif in_gcp_project and not has_variant_key and not injected and re.search(r"^\s+id:\s+", line):
            new_lines.append(line)
            indent = len(line) - len(line.lstrip())
            new_lines.append(f"{' ' * indent}policy_tier: genai_sandbox")
            injected = True
            in_gcp_project = False
        else:
            new_lines.append(line)

    with open(ql_yaml_path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines) + "\n")

    return True, "Updated to policy_tier: genai_sandbox"


def update_inventory_csv(inv_path, slug, status, pr_url=None, bug_id=None, recommendation=None):
    """Update a row in sample_fleet_inventory.csv."""
    if not inv_path or not os.path.exists(inv_path):
        return
    rows = []
    fieldnames = []
    with open(inv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        for extra in ["pr_url", "bug_id"]:
            if extra not in fieldnames:
                fieldnames.append(extra)
        for row in reader:
            if row.get("slug") == slug:
                row["status"] = status
                if pr_url:
                    row["pr_url"] = pr_url
                if bug_id:
                    row["bug_id"] = bug_id
                if recommendation:
                    row["recommendation"] = recommendation
            rows.append(row)
    with open(inv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def process_single_lab(slug, repo_root, dry_run=False, inv_path=None):
    """Execute complete migration workflow for one lab."""
    lab_path = os.path.join(repo_root, "labs", slug)
    if not os.path.exists(lab_path):
        print(f"[-] Lab directory does not exist: {lab_path}")
        if not dry_run:
            update_inventory_csv(inv_path, slug, "REMOVED_FROM_REPO", recommendation="Directory removed from main")
        return False

    print(f"\n[{slug}] Starting migration...")

    # Step 1: Preflight Audit
    script_dir = os.path.dirname(os.path.abspath(__file__))
    audit_script = os.path.join(script_dir, "audit_genai_sandbox.py")
    if not os.path.exists(audit_script):
        audit_script = os.path.join(repo_root, ".agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/audit_genai_sandbox.py")
    res = run_cmd(["python3", audit_script, lab_path, "--json"], check=False)
    if res.returncode != 0:
        print(f"[-] Audit script failed for {slug}: {res.stderr}")
        return False

    audit_data = json.loads(res.stdout)
    status = audit_data.get("status", "")
    if not audit_data.get("is_llm_lab") or status == "NON_LLM_LAB":
        print(f"[!] SKIP: {slug} is a non-LLM/non-Foundation-Model lab ({status}). Retained on standard_sandbox.")
        if not dry_run:
            update_inventory_csv(inv_path, slug, "NON_LLM_LAB", recommendation="Retained on standard_sandbox (not a Foundation Model lab)")
        return False

    if audit_data.get("has_managed_ide") or status == "managed_ide_proxy_EXCLUDED":
        print(f"[!] SKIP: {slug} uses Managed Web IDE Proxy ({audit_data.get('managed_ide_types')}). Excluded from genai_sandbox.")
        if not dry_run:
            update_inventory_csv(inv_path, slug, "managed_ide_proxy_EXCLUDED", recommendation=audit_data.get("recommendation"))
        return False

    if audit_data.get("has_manual_sa_keys") or status == "REQUIRES_WORKAROUND_SA_KEY":
        print(f"[!] SKIP: {slug} requires SA key workaround. Do not migrate yet.")
        if not dry_run:
            update_inventory_csv(inv_path, slug, "REQUIRES_WORKAROUND_SA_KEY", recommendation=audit_data.get("recommendation"))
        return False

    if status == "COMPLIANT" or audit_data.get("compliant"):
        print(f"[✓] SKIP: {slug} is already compliant.")
        if not dry_run:
            update_inventory_csv(inv_path, slug, "MERGED_COMPLIANT", recommendation="Already on policy_tier: genai_sandbox")
        return True

    if dry_run:
        print(f"[DRY RUN] Would migrate {slug} to policy_tier: genai_sandbox and open PR.")
        return True

    # Step 2: Branching
    branch_name = f"feat/gcp-llm-fleet-{slug}"
    run_cmd(["git", "checkout", "main"], cwd=repo_root)
    run_cmd(["git", "checkout", "-B", branch_name, "origin/main"], cwd=repo_root)

    # Step 3: Refactor YAML
    success, msg = migrate_lab_yaml(lab_path)
    if not success:
        print(f"[-] YAML update failed: {msg}")
        return False

    # Step 4: Validate
    res = run_cmd(["python3", audit_script, lab_path, "--json"], check=False)
    post_audit = json.loads(res.stdout)
    if post_audit.get("status") != "COMPLIANT" and not post_audit.get("compliant"):
        print(f"[-] Post-flight audit failed: {post_audit}")
        return False

    # Step 5: Commit & Push
    run_cmd(["git", "add", f"labs/{slug}/sandbox.yaml"], cwd=repo_root)
    run_cmd(["git", "commit", "-m", f"feat(fleet): migrate {slug} to genai_sandbox fleet variant"], cwd=repo_root)
    run_cmd(["git", "push", "-f", "-u", "origin", branch_name], cwd=repo_root)

    # Step 6: Create Child GitHub Issues Ticket
    child_bug_id = create_gh issue_ticket(slug)
    bug_md = f"[b/{child_bug_id}](http://b/{child_bug_id})" if child_bug_id else f"[b/{PARENT_BUG_ID}](http://b/{PARENT_BUG_ID})"

    # Step 7: Open PR
    pr_body = (
        "### Summary of Changes\n"
        f"- Migrated `sandbox.yaml` `gcp_project` to `policy_tier: genai_sandbox`.\n"
        "- Audited for absence of manual service account key creation and Managed Web IDE Proxy (`ide`/`cloud_terminal`) resources.\n"
        "- Preflight validation: `audit_genai_sandbox.py` passed (Status: COMPLIANT).\n\n"
        f"**Tracking Issue**: {bug_md}\n"
        f"**Parent Initiative**: [b/{PARENT_BUG_ID}](http://b/{PARENT_BUG_ID})\n"
        f"**Rollout Campaign**: `{CAMPAIGN_TAG}`\n"
        f"**Assignee**: `{ASSIGNEE_LDAP}`\n"
    )

    pr_cmd = [
        "gh", "pr", "create",
        "--repo", "example-org/cloud-sandboxes",
        "--head", branch_name,
        "--base", "main",
        "--title", f"feat(fleet): migrate {slug} to genai_sandbox fleet variant",
        "--body", pr_body,
        "--label", CAMPAIGN_TAG,
        "--label", f"bug:{PARENT_BUG_ID}",
        "--label", "variant:genai_sandbox"
    ]
    pr_res = run_cmd(pr_cmd, cwd=repo_root, check=False)
    pr_url = ""
    if pr_res.returncode == 0:
        pr_url = pr_res.stdout.strip()
        print(f"[✓] PR Created: {pr_url} (Bug: {bug_md})")
    else:
        # Check if PR already exists
        existing = run_cmd(["gh", "pr", "list", "--repo", "example-org/cloud-sandboxes", "--head", branch_name, "--json", "url", "--jq", ".[0].url"], cwd=repo_root, check=False)
        pr_url = existing.stdout.strip()
        print(f"[!] PR already exists or returned {pr_res.returncode}: {pr_url} / {pr_res.stderr.strip()}")

    update_inventory_csv(
        inv_path,
        slug,
        "PR_OPENED",
        pr_url=pr_url,
        bug_id=f"b/{child_bug_id}" if child_bug_id else f"b/{PARENT_BUG_ID}",
        recommendation="Migrated to policy_tier: genai_sandbox; PR opened.",
    )

    # Return to main
    run_cmd(["git", "checkout", "main"], cwd=repo_root)
    return True


def main():
    parser = argparse.ArgumentParser(description="Batch migrate GenAI labs to genai_sandbox fleet variant.")
    parser.add_argument("--repo-root", default=".", help="Path to cloud-sandboxes repository root")
    parser.add_argument("--inventory-csv", default=None, help="Path to sample_fleet_inventory.csv (defaults to assets/)")
    parser.add_argument("--slugs", nargs="+", help="Specific lab slugs to migrate")
    parser.add_argument("--all", action="store_true", help="Migrate all identified LLM labs from inventory")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of labs to migrate in this run")
    parser.add_argument("--dry-run", action="store_true", help="Audit and preview without modifying files or opening PRs")

    args = parser.parse_args()
    repo_root = os.path.abspath(args.repo_root)

    default_inv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../assets/sample_fleet_inventory.csv")
    inv_path = args.inventory_csv or default_inv
    if not os.path.exists(inv_path):
        inv_path = os.path.join(repo_root, ".agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/assets/sample_fleet_inventory.csv")

    targets = []
    if args.slugs:
        targets = args.slugs
    elif args.all:
        if not os.path.exists(inv_path):
            print(f"[-] Master inventory CSV not found at {inv_path}")
            sys.exit(1)
        with open(inv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Target is genai_sandbox and no manual SA keys detected
                has_no_keys = row.get("has_manual_sa_keys", "NO").upper() in ("NO", "FALSE")
                if row.get("target_variant") == "genai_sandbox" and has_no_keys:
                    if row.get("current_variant") != "genai_sandbox":
                        targets.append(row["slug"])
    else:
        print("[-] Must specify --slugs <slug1>... or --all")
        sys.exit(1)

    if args.limit:
        targets = targets[:args.limit]

    print(f"[*] Found {len(targets)} candidate lab(s) for migration.")
    success_count = 0
    for slug in targets:
        if process_single_lab(slug, repo_root, dry_run=args.dry_run, inv_path=inv_path):
            success_count += 1

    print(f"\n[+] Finished batch run: {success_count}/{len(targets)} lab(s) successfully processed.")


if __name__ == "__main__":
    main()
