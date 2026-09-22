#!/usr/bin/env python3
"""Batch orchestrator for catalog-scale lab hardening.

Can dynamically fetch top-risk labs from the security engine or process a specific lab.
Spawns background Claude Code / Gemini CLI/AgentAPI tasks with pre-configured hardening workflows.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("orchestrate-hardening")

# Ensure mcp directory is importable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.dirname(SCRIPT_DIR)
MCP_DIR = os.path.join(PLUGIN_DIR, "mcp")
sys.path.insert(0, MCP_DIR)

from security_engine import SecurityEngine


import re

# GitHub Issues Rollout Metadata
PARENT_BUG_ID = "SEC-100"  # [Project Phase] Apply Hardening to all sandboxes
BUG_COMPONENT_ID = "1939024"  # Lab Architects project component
CAMPAIGN_TAG = "cloud-sandbox-security-hardening"


def create_gh issue_ticket(slug: str, parent_id: str = PARENT_BUG_ID, assignee: str = "training-qa-testers@google.com"):
    """Creates a child GitHub Issues issue linked to the parent rollout ticket."""
    title = f"QA Staging: Harden {slug}"
    desc = (
        f"Security hardening and anti-abuse implementation for `{slug}`.\n\n"
        f"* **Parent Initiative**: http://b/{parent_id}\n"
        f"* **Repository**: example-org/cloud-sandboxes\n"
        f"* **Rollout Campaign**: `{CAMPAIGN_TAG}`\n\n"
        f"### 🧪 QA Testing Scope & Guidelines (Security Hardening Review)\n"
        f"**STRICT QA TESTING BOUNDARY:**\n"
        f"* **What to test for**: You are validating whether our security patch caused a regression:\n"
        f"  1. `403 PERMISSION_DENIED` errors on student commands.\n"
        f"  2. Network timeouts on required downloads (e.g. `pip install`, `apt`, `curl`).\n"
        f"* **Baseline Defect Decoupling**: If the lab fails due to an existing baseline issue (e.g. Activity Tracking script syntax error, deprecated OS image, third-party software bug, or console UI rename unrelated to IAM/Egress):\n"
        f"  - **Do NOT block this PR.**\n"
        f"  - Confirm whether the issue also occurs on the production/main baseline.\n"
        f"  - If it is a pre-existing baseline defect, reply confirming that no IAM/Egress regressions were encountered. We will approve the security PR and file a separate ticket for content maintainers.\n"
    )
    try:
        cmd = [
            "gh issue", "create-issue",
            "--component-id", BUG_COMPONENT_ID,
            "--title", title,
            "--comment-markdown", desc,
            "--priority", "P2",
            "--severity", "S2",
            "--status", "ASSIGNED",
            "--assignee", assignee,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            match = re.search(r"\b(\d{8,10})\b", res.stdout)
            if match:
                child_id = match.group(1)
                subprocess.run(
                    ["gh issue", "add-issue-parent", "--issue-id", child_id, "--parent-id", parent_id],
                    capture_output=True,
                )
                return child_id
    except Exception:
        pass
    return None


def setup_worktree(repo_root: str, slug: str, branch_name: str) -> str:
    """Sets up an isolated git worktree for a target lab to eliminate .git/index.lock contention."""
    wt_base = os.path.join(tempfile.gettempdir(), "cloud-sandbox-security-worktrees")
    os.makedirs(wt_base, exist_ok=True)
    wt_dir = os.path.join(wt_base, f"wt-{slug}")

    if os.path.exists(wt_dir):
        subprocess.run(["git", "worktree", "remove", wt_dir, "--force"], cwd=repo_root, capture_output=True)

    # Ensure remote tracking branch is fresh
    subprocess.run(["git", "fetch", "origin", "main"], cwd=repo_root, capture_output=True)

    cmd = ["git", "worktree", "add", "-B", branch_name, wt_dir, "origin/main"]
    res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    if res.returncode != 0:
        logger.warning(f"Could not branch from origin/main, trying HEAD: {res.stderr}")
        cmd = ["git", "worktree", "add", "-B", branch_name, wt_dir, "HEAD"]
        subprocess.run(cmd, cwd=repo_root, check=True, capture_output=True)
    return wt_dir


def cleanup_worktree(repo_root: str, wt_dir: str):
    """Safely prunes an isolated git worktree after PR creation."""
    if os.path.exists(wt_dir):
        subprocess.run(["git", "worktree", "remove", wt_dir, "--force"], cwd=repo_root, capture_output=True)


def spawn_hardening_agent(
    lab_slug: str,
    repo_root: str,
    parent_id: str = PARENT_BUG_ID,
    use_worktree: bool = True,
    dry_run: bool = False,
):
    """Spawns an agent conversation to harden a target lab with worktree isolation."""
    branch_name = f"feat/hardening-{lab_slug}"
    target_workspace = repo_root

    if dry_run:
        wt_note = " (in isolated git worktree)" if use_worktree else ""
        print(f"[DRY RUN] Would create GitHub Issues child issue under b/{parent_id} and spawn agent for: {lab_slug}{wt_note}")
        return

    child_bug_id = create_gh issue_ticket(lab_slug, parent_id=parent_id)
    bug_ref = f" (b/{child_bug_id})" if child_bug_id else ""
    if child_bug_id:
        print(f"Created child GitHub Issues ticket: b/{child_bug_id} (linked to parent b/{parent_id})")

    if use_worktree:
        try:
            target_workspace = setup_worktree(repo_root, lab_slug, branch_name)
            print(f"Provisioned isolated worktree at: {target_workspace}")
        except Exception as e:
            print(f"[-] Worktree setup failed ({e}). Falling back to main repository.")
            target_workspace = repo_root

    prompt = (
        f"Please apply the harden-sandbox skill to harden '{lab_slug}' in repository workspace '{target_workspace}'.\n"
        f"1. Run recommend_iam_roles('{lab_slug}') and explain_pitfall('{lab_slug}').\n"
        f"2. Apply security patches for egress firewall and scoped IAM roles.\n"
        f"3. Run validate_pre_merge('{lab_slug}') until PASS.\n"
        f"4. Lockfile & Cache Hygiene: rm -rf labs/{lab_slug}/tf/.terraform labs/{lab_slug}/tf/.terraform.lock.hcl\n"
        f"5. Run git pre-commit checks.\n"
        f"6. Commit modified files on branch '{branch_name}' with:\n"
        f"   feat(security): harden {lab_slug} least-privilege IAM and egress network\n\n"
        f"   BUG={child_bug_id or '<BUG_ID>'}\n"
        f"7. Push and open Pull Request matching the Agentic Mass Update Playbook:\n"
        f"   git push origin {branch_name}\n"
        f"   gh pr create \\\n"
        f"     --title 'feat(security): harden {lab_slug} least-privilege IAM and egress network' \\\n"
        f"     --body '### Summary of Changes\\n- Hardened least-privilege IAM and egress firewall.\\n- validate_pre_merge passed.\\n\\n**Tracking Issue**: [b/{child_bug_id or '<BUG_ID>'}](http://b/{child_bug_id or '<BUG_ID>'})\\n**Parent Initiative**: [b/{parent_id}](http://b/{parent_id})\\n**Rollout Campaign**: `{CAMPAIGN_TAG}`\\n**Assignee**: `training-qa-testers@google.com`' \\\n"
        f"     --label '{CAMPAIGN_TAG}' \\\n"
        f"     --label 'bug:{parent_id}' \\\n"
        f"     --label 'security' \\\n"
        f"     --label 'anti-abuse'\n"
    )

    cmd = [
        "agentapi", "new-conversation",
        "--title", f"Hardening: {lab_slug}{bug_ref}",
        "--model", "pro",
        prompt
    ]
    print(f"Spawning agent for {lab_slug}...")
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(description="Orchestrate Cloud Lab catalog hardening.")
    parser.add_argument("--slug", type=str, help="Specific lab slug to harden.")
    parser.add_argument("--batch-size", type=int, default=5, help="Number of high-risk labs to process dynamically.")
    parser.add_argument("--repo-root", type=str, default=os.path.expanduser("~/repos/cloud-sandboxes"), help="Path to lab repo.")
    parser.add_argument("--parent-bug", type=str, default=PARENT_BUG_ID, help="Parent GitHub Issues issue ID (default: SEC-100).")
    parser.add_argument("--worktree", action="store_true", default=True, help="Use isolated git worktrees to prevent lock contention (default True).")
    parser.add_argument("--no-worktree", dest="worktree", action="store_false", help="Disable git worktree isolation.")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without spawning agents.")
    args = parser.parse_args()

    engine = SecurityEngine(plugin_dir=PLUGIN_DIR, lab_repo_root=args.repo_root)

    if args.slug:
        targets = [args.slug]
    else:
        print(f"Scanning catalog under {args.repo_root}/labs for high-risk backlog...")
        backlog_res = engine.get_backlog(limit=args.batch_size)
        targets = [item["slug"] for item in backlog_res.get("backlog", [])]

    print(f"Targeting {len(targets)} lab(s): {targets}")
    for slug in targets:
        spawn_hardening_agent(
            slug,
            repo_root=args.repo_root,
            parent_id=args.parent_bug,
            use_worktree=args.worktree,
            dry_run=args.dry_run,
        )


if __name__ == "__main__":
    main()
