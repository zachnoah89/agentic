---
name: harden-sandbox
description: >
  Use this skill when asked to harden, remediate, or apply least-privilege IAM
  and network egress isolation to a Google Cloud ephemeral cloud sandbox, or when fixing
  privilege escalation vulnerabilities (removing roles/owner, roles/editor, or
  project-level service account admin). Guides the end-to-end remediation
  workflow, development IAM admin setup, and mandatory pre-merge validation
  gates. Do NOT use for hands-on penetration testing or proof-of-concept
  vulnerability verification (use pentest-sandbox instead).
---

# 🛡️ Cloud Lab Hardening Skill (`harden-sandbox`)

A skill for auditing, least-privilege scoping, and network isolation on Google Cloud ephemeral cloud sandbox content to eliminate abuse vectors while preserving lab educational objectives.

## Overview

You are an expert Google Cloud Security Architect for Cloud Lab content. Your goal is to systematically harden labs to prevent crypto-mining and service account key exfiltration while ensuring student learning tasks and automated Ruby/Python assessment checks remain completely functional.

---

## ⚠️ Gotchas (Hardening Traps & Failure Modes)

Before applying patches, keep these critical platform behaviors in mind to avoid breaking lab functionality or creating security gaps:

1. **The Multi-Harness Sync Trap**:
   Labs often contain secondary harnesses (`cleanup/`, `setup/`, `teardown/`, or `terraform-files/`). Hardening only `tf/` will cause teardown scripts to fail during student de-provisioning or leave live security holes in setup infrastructure. Synchronize egress firewalls and IAM roles across **all** active harnesses.
2. **The Residual Dev Admin Trap (`roles/resourcemanager.projectIamAdmin`)**:
   Adding `projectIamAdmin` during development allows fast iteration, but forgetting to delete it before submitting a PR will cause an immediate hard failure at the mandatory `validate_pre_merge` gate.
3. **The Silent SSH Assessment Trap (`user_0.SSH`)**:
   Automated Ruby assessment checks using `user_0.SSH` fail silently with generic "Task not completed" errors if any of the **SSH Quartet** roles are missing: `roles/compute.osLogin`, `roles/iam.serviceAccountUser`, `roles/iap.tunnelResourceAccessor`, and `roles/compute.viewer`.
4. **Service Usage Quota Consumption**:
   Modern CLI tools (`gcloud`, `bq`, `cbt`) verify project quota allocations using the Service Usage API. Always include `roles/serviceusage.serviceUsageConsumer` in `sandbox.yaml` to prevent cryptic `403` errors.
5. **Bigtable DDL vs. Data Operations**:
   `roles/bigtable.user` only permits data read/write. If instructions require `cbt createtable` or `cbt createfamily`, you must grant `roles/bigtable.admin`.
6. **The Managed Web IDE Proxy (`ide-provisioner@`) & Exported SA Key Control-Plane Bypass (`SEC-001`)**:
   - **Managed Web IDE Proxy (`ide`, `cloud_terminal`, `looker_instance`, `jupyter_notebook`)**: These containers run in Cloud Sandbox Platform' central GKE cluster (`sandbox-platform-prod`, outside the student VPC) and use `ide-provisioner@` (which is exempted from the `genai_sandbox` IAM Deny policy in `Policy-Deny-SA-Keys`) to inject `/home/user/keys.json` with project-wide permissions. **NEVER pair Managed Web IDE Proxy resources with `policy_tier: genai_sandbox`**.
   - **Why `tf/secure_network.tf` Does Not Protect Exported SA Keys (`google_service_account_key`)**: `secure_network.tf` is a Data-Plane VPC firewall that protects **VM-attached Service Accounts** (whose access tokens stay inside the GCE VM via IMDSv2 `169.254.169.254`). Once an exportable JSON key (`google_service_account_key` or `/home/user/keys.json`) is copied out of the browser, attackers invoke `https://aiplatform.googleapis.com` directly over the public internet (Control Plane), bypassing `tf/secure_network.tf` 100%.
7. **The Missing `runtime.yaml` Script Runner Launch Failure (`SEC-004`)**:
   Whenever security hardening establishes or wires a Terraform startup script in `sandbox.yaml` (`path: tf` or `path: ./tf` for `secure_network.tf` or SA scoping), `runtime.yaml` is **strictly mandatory**. If omitted, the Cloud Sandbox Platform script runner rejects the script bundle during lab launch with:
   `Sorry, cannot start Lab. Resources failed to launch: project 0 (error uploading script to script runner: bad request, invalid script: missing runtime.yaml file.)`
   Ensure `<path>/runtime.yaml` declares:
   ```yaml
   runtime: terraform
   version: 1.12.1
   ```

---

## 📋 Hardening Execution Checklist

Track progress sequentially through these steps during each lab hardening task:

- [ ] **Step 0: Exception Check & Triage**: Run `check_exception` and check for approved exceptions or pure SaaS/Cloud Shell labs.
- [ ] **Step 1: Role Discovery & Pitfall Review**: Run `recommend_iam_roles` and review known failure modes with `explain_pitfall`.
- [ ] **Step 2: Temporary Dev IAM Admin**: Add `roles/resourcemanager.projectIamAdmin` to `sandbox.yaml` for local iteration.
- [ ] **Step 3: Phase 1 (IAM Hardening)**: Strip broad roles (Owner/Editor) and apply scoped resource-level roles.
- [ ] **Step 4: Phase 2 (Network & Host Hardening)**: Deploy `secure_network.tf` and enforce IMDSv2 across ALL active harnesses.
- [ ] **Step 5: Mandatory Pre-Merge Gate**: Delete dev IAM admin and run `validate_pre_merge` (MUST return `PASS`).
- [ ] **Step 6: Continuous Learning**: Record any newly discovered grading quirks into `kb/pitfalls.yaml`.

---

## 🔍 Retrieval Contract: Determining Required Roles

> [!IMPORTANT]
> **Do NOT guess or extrapolate roles from memory.**
> Cloud Lab Platform services and assessment engines have strict quirks that are cataloged deterministically in the `cloud-sandbox-security` MCP server. Always follow the **Two-Tier Grounding Protocol**.

### Tier 1: Platform Scoping & Nuance (Mandatory First Step)
Before modifying any permissions:
1. **Discover Scoped Roles:** Call `recommend_iam_roles(lab_slug="<lab-slug>")`.
   This inspects the lab's Terraform resources, assessment scripts, and instructions, matching them against curated archetypes and outputting the minimal role list.
2. **Review Traps & Failure Modes:** Call `explain_pitfall(lab_slug="<lab-slug>")` to retrieve critical gotchas (e.g. `cbt` DDL requirements, reasoning engine location constraints, or silent SSH assessment failures).
3. **Audit Current State:** Call `audit_lab(lab_slug="<lab-slug>")` to identify current vulnerabilities and instruction formatting issues.

### Tier 2: Official Upstream Grounding & Fallback (When Required)
Invoke external grounding MCP servers (`google-developer-knowledge`, `terraform-registry`) **after** Tier 1 under these conditions:
1. **Unclassified APIs / New Services:** If `recommend_iam_roles` reports `unclassified_resources` (services not yet cataloged in `roles.yaml`), query `google-developer-knowledge` (`search_documents` or `answer_query`) for the official least-privilege IAM roles.
2. **Granular Action Verification:** If custom IAM roles or fine-grained API methods are required, vet against Google Developer Knowledge documentation.
3. **Terraform Syntax Validation:** If provisioning new resources or adjusting network/firewall schemas, verify provider arguments using `terraform-registry` (`resourceArgumentDetails`).

---

## 📋 Step 0: Check Exceptions Registry & False-Positive Triage

1. **Check Exception Registry (`check_exception`)**: Before refactoring or hardening a lab, call `check_exception(lab_slug="<lab-slug>")` or inspect `kb/exceptions.yaml`.
   - If status is `APPROVED_EXCEPTION` (e.g. `intentional_vulnerability` in a security challenge lab or `third_party_egress` for AWS/Datadog integrations), do NOT alter the approved intentional behavior. Reference the tracking GitHub Issues bug.
2. **False-Positive Taxonomy & `INTENDED_BEHAVIOR` Resolution**:
   - If `audit_lab` reports `is_pure_saas_or_cloud_shell: true` (0 GCP VMs, 0 network firewalls, runs entirely in Cloud Shell or BigQuery Studio web console), do NOT establish dummy Terraform harnesses or dummy firewall rules.
   - Comment on the GitHub Issues tracking ticket with technical justification and close as `INTENDED_BEHAVIOR`.

---

## 🔑 Mandatory Step 1: Development IAM Admin Setup

During local testing and development:

1. **Add `roles/resourcemanager.projectIamAdmin`**:
   Temporarily grant `- roles/resourcemanager.projectIamAdmin` to `user_0` in `sandbox.yaml`:
   ```yaml
   permissions:
     - project: project_0
       roles:
         - roles/viewer
         # ... lab specific roles ...
         - roles/resourcemanager.projectIamAdmin
   ```
2. **Purpose**:
   - Allows instant testing and on-the-fly troubleshooting in Cloud Shell without waiting 20 minutes to reprovision a lab.
   - Restricted strictly to IAM policy management (cannot modify infrastructure).

---

## 🔒 Mandatory Step 2: 3-Phase Hardening Playbook

### 1. Phase 1: Baseline IAM Least Privilege
- **Strip Dangerous Roles**: Remove `roles/owner` and `roles/editor` from `sandbox.yaml` and `.tf` files.
- **Apply Scoped Roles**: Replace with the exact roles returned by `recommend_iam_roles`. Always include baseline `roles/viewer` and `roles/serviceusage.serviceUsageConsumer`.
- **Zero Project-Level SA Admin/User**: NEVER grant `roles/iam.serviceAccountAdmin` or `roles/iam.serviceAccountUser` at the project level in `sandbox.yaml`.
  - *Privilege Escalation Trap*: Project-level SA admin allows binding `roles/iam.serviceAccountTokenCreator` on the default Compute SA (which has Editor rights).
  - *Remediation*: Scope permissions in Terraform via `google_service_account_iam_member` bound to `user:${var.username}` directly on the specific custom SA.
- **IAM Curriculum Labs (`tf/iam_delegated.tf` & `--condition=None` CLI Requirement)**:
  - When a lab teaches `gcloud projects add-iam-policy-binding` or `gcloud iam service-accounts create`, replace project-level `roles/resourcemanager.projectIamAdmin` in `sandbox.yaml` with `tf/iam_delegated.tf` (`modifiedGrantsByRole` CEL condition allowing ONLY the exact curriculum roles + `google_project_default_service_accounts` `action = "DEPRIVILEGE"`).
  - **Crucial CLI Pitfall (`gcloud-conditional-iam-policy-interactive-prompt`)**: Because `tf/iam_delegated.tf` adds a conditional binding to the project IAM policy, `gcloud projects add-iam-policy-binding` will prompt interactively (`Specify the condition...`) or fail in `--quiet` mode unless `--condition=None` is passed. Always append `--condition=None` to every `gcloud projects add-iam-policy-binding` command in `instructions/en.md` when `tf/iam_delegated.tf` is present.
- **Prefer Attached VM SAs over `google_service_account_key`**: Attach `google_service_account` to GCE VMs with `disable-legacy-endpoints = "TRUE"` so access tokens never leave the `secure_network.tf` VPC perimeter. NEVER mint a `google_service_account_key` in a `genai_sandbox` lab or on an SA with `roles/aiplatform.user`, `roles/editor`, or `roles/owner`. If a non-LLM lab strictly requires a `google_service_account_key`, scope it to a single non-LLM role with an IAM `request.time < ...` expiry condition (`assets/pre_provisioned_sa_key.tf.template`).

### 2. Phase 2: Network & Compute Isolation
- **Egress Firewall**: Deny `0.0.0.0/0` outbound (priority 1000). Allow only HTTP (80), HTTPS (443), DNS (53), NTP (123) outbound (priority 900). Apply via `apply_security_patch(lab_slug=..., patch_type="egress_firewall")`.
- **Enforce IMDSv2**: Set `disable-legacy-endpoints = "TRUE"` on Compute instances.
- **Mandatory `runtime.yaml`**: Ensure all Terraform directories wired to `startup_script` (or secondary harnesses) contain `runtime.yaml` (`runtime: terraform`, `version: 1.12.1`). Missing `runtime.yaml` causes the Cloud Sandbox Platform script runner to reject script upload at launch (`SEC-004`).
- **Multi-Harness Synchronization**: Inspect all active Terraform harnesses (`tf/`, `terraform/`, `cleanup/`, `setup/`, `teardown/`). Synchronize egress firewalls and scoped IAM across **all** active harnesses in the lab bundle to prevent teardown failures or security holes during teardown.

### 3. Phase 3: Platform Perimeter & Quota Boundaries
- Platform-enforced by Navy variants (`genai_sandbox`, `standard_sandbox` Base Types & custom producer quotas). At the lab level, rely on Cloud NAT private subnets where applicable. (See `references/platform_security_roadmap.md` for org-level boundary details).

### 4. Phase 4: Mini-Lab, `cloud_terminal` (`ManagedWebIDE`), Custom Roles (`noVmCreate`), & Custom IDEs
Mini-labs (`15–20 min` bite-sized labs) and labs using browser-based terminal or IDE environments require specific handling due to Cloud Lab Platform backend behaviors:

* **A. NEVER Pair ManagedWebIDE with `genai_sandbox` (`SEC-001`)**:
  - Do NOT combine `cloud_terminal`, `ide`, `looker_instance`, or `jupyter_notebook` resources with `policy_tier: genai_sandbox`. ManagedWebIDE (`ide-provisioner@`) is exempted from the `genai_sandbox` IAM Deny policy (`Policy-Deny-SA-Keys`) and injects an exportable `/home/user/keys.json` into a GKE container in `sandbox-platform-prod`, allowing students to copy the key out and call `https://aiplatform.googleapis.com` from outside the VPC.

* **B. `cloud_terminal` Schema & Backend Constraint (`cloud_terminal: true` / `type: cloud_terminal`)**:
  - **The Platform Reality**: Cloud Sandbox Platform Schema v2 strictly requires `roles/editor` on `cloud_terminal` resources in `sandbox.yaml` (stripping it causes `"Resources failed to launch: shell"`). Furthermore, the backend provisioner **ignores custom YAML roles** and hardcodes the student's terminal credentials to receive **`roles/owner`, `roles/storage.admin`, and `roles/bigquery.admin`**.
  - **Remediation Option 1 (Preferred if GCP Console access is acceptable)**: Migrate the resource from `type: cloud_terminal` to `type: gcp_user` with native Cloud Shell and apply scoped least-privilege roles in `sandbox.yaml`.
  - **Remediation Option 2 (When `cloud_terminal` is strictly required by mini-lab spec on non-LLM fleets)**:
    - Leave `roles/editor` on the `cloud_terminal` block in `sandbox.yaml` so the container launches cleanly.
    - **NEVER use an authoritative `google_project_iam_policy` in `terraform-files/main.tf` to overwrite project IAM without preserving `serviceAccount:ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com` (`roles/owner`) and Google service agents (`compute`, `cloudbuild`, `aiplatform`)!** Stripping `ide-provisioner@` breaks assessment grading and leaves orphaned resources (`mini-lab-09` pitfall).
    - Instead, avoid authoritative `google_project_iam_policy` overwrites altogether or register the lab in `kb/exceptions.yaml` under `cloud_terminal_spec`.

* **C. Avoid Authoritative IAM Policies (`google_project_iam_policy`) & `noVmCreate` Anti-Patterns**:
  - **Launch Deadlock Trap**: Applying an authoritative `google_project_iam_policy` that omits `ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com` revokes `ide-provisioner@`'s permissions mid-startup, causing `cloud_terminal` or `ide` provisioning to fail (`TF_AUTHORITATIVE_POLICY_OMITS_ORCHESTRATOR`).
  - **Deceptive IAM Override (`TF_DECEPTIVE_IAM_POLICY_OVERRIDE`)**: Never leave `roles/editor` or `roles/owner` in `sandbox.yaml` relying on Terraform `google_project_iam_policy` to strip it later; declare least-privilege roles directly in `sandbox.yaml`.
  - **Why `google_project_iam_custom_role` (`noVmCreate`) Fails (`TF_CUSTOM_ROLE_NOVMCREATE_MIG_BYPASS`)**: Removing `compute.instances.create` from `roles/editor` via a custom role is trivially bypassed in two ways:
    1. **MIG Resize / Cloud Build / GKE Node Pool Bypass**: `compute.instanceGroupManagers.update` remains in the custom role, allowing students to create an Instance Template and scale a Managed Instance Group (`gcloud compute instance-groups managed create ... --size=1`), where Google's Managed Instance Group service agent calls `compute.instances.create` on their behalf.
    2. **Default Compute SA `roles/editor` Token Theft (`TF_DEFAULT_COMPUTE_SA_EDITOR_EXPOSURE`)**: If any Compute VM, GKE node, or Cloud Run service runs in the project with the Default Compute Service Account (`<project-number>-compute@developer.gserviceaccount.com`), the student uses `compute.instances.setMetadata` (`gcloud compute instances add-metadata --metadata=startup-script=...`) or `gcloud compute ssh` to fetch the Default Compute SA's full `roles/editor` access token from IMDS (`http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`), regaining `compute.instances.create`.
  - **Remediation**: Replace `noVmCreate` custom roles and `google_project_iam_policy` blocks with positive least-privilege standard roles in `sandbox.yaml` (`recommend_iam_roles`), and attach a dedicated low-privilege `google_service_account` to any lab VMs instead of the Default Compute SA.

* **D. Securing Compute Workloads Spawned by Mini-Labs (`terraform-files/` VPC Isolation)**:
  - Even though the `cloud_terminal` shell container itself runs in Google's tenant VPC (*outside* `project_0`'s VPC), **any GCE VMs, GKE nodes, or Vertex Workbench instances provisioned in `terraform-files/` DO run inside `project_0` VPC** and are prime targets for crypto-mining.
  - You **MUST** deploy `secure_network.tf` (egress firewall) and `disable-legacy-endpoints = "TRUE"` (IMDSv2) into the mini-lab's active Terraform directory (`terraform-files/` or `tf/`).

* **E. Protecting Browser-Based Custom IDEs (`custom_ide` / Code OSS / Vertex Workbench)**:
  - Unlike `cloud_terminal`, VM-backed custom IDEs run on Compute Engine instances *inside* `project_0` VPC and ARE governed by `secure_network.tf`.
  - **Mandatory IAP Firewall Rule**: When deploying `secure_network.tf` to a lab with a VM-backed IDE, ensure ingress/egress allow rules permit **Identity-Aware Proxy (IAP) TCP forwarding (`35.235.240.0/20` on TCP ports 22, 80, 443, 8080)** and Private Google Access. Otherwise, the student's browser IDE will fail to connect with a `502 Bad Gateway`.

---

## ✅ Mandatory Step 3: Pre-Merge Verification Gate

> [!CAUTION]
> **MANDATORY PRE-MERGE GATE**: You MUST run pre-merge validation before creating a PR.

Before submitting a Pull Request:
1. **Delete Development IAM Admin**: Open `sandbox.yaml` and **delete** `- roles/resourcemanager.projectIamAdmin`.
2. **Ephemeral Cache & Lockfile Hygiene**: Purge local build artifacts before staging:
   ```bash
   rm -rf labs/<lab-slug>/tf/.terraform labs/<lab-slug>/tf/.terraform.lock.hcl
   ```
3. **Run Gate**: Call `validate_pre_merge(lab_slug="<lab-slug>")`.
4. **Requirement**: `validate_pre_merge` MUST return `"status": "PASS"` (or `"PASS_WITH_EXCEPTION"` if an approved exception is on file). If it returns `"FAIL"`, address all listed blocking violations.
5. **Git Pre-commit**:
   ```bash
   python3 -m pre_commit run --files $(git diff --staged --name-only)
   ```

---

## 🧪 Optional Step 4: Live Staging Verification via `/execute-lab` (Opt-In)

> [!NOTE]
> **Optional & Non-Invasive Integration**: Live execution via the `/execute-lab` skill is **strictly optional (opt-in)** and does **NOT** modify any files in `skills/execute-lab/`. Invoke `/execute-lab` only when the user explicitly requests live staging verification or provides a registered staging `lab_id` on `gcpstaging.sandbox-platform.com`.

### When to Trigger `/execute-lab`:
1. **User Opt-In**: The user asks to run end-to-end live testing after hardening (e.g., *"harden this lab and run `/execute-lab` to verify"*) or supplies a staging URL (`https://gcpstaging.sandbox-platform.com/authoring/labs/<LAB_ID>`).
2. **Complex IAM / Delegated Role Grant Verification**: You are testing a newly hardened IAM curriculum lab (`tf/iam_delegated.tf`), custom VPC firewall (`tf/secure_network.tf`), or custom service account setup and want live proof that student tasks and negative security controls both pass.

### How `harden-sandbox` Pairs with `/execute-lab`:
1. **Phase A — Static Hardening (`harden-sandbox`)**: Complete Steps 1–3 above (`validate_pre_merge` = `PASS`) and push the feature branch (`feat/hardening-<lab-slug>`) or open the staging PR so `gcpstaging.sandbox-platform.com` builds the updated lab bundle.
2. **Phase B — Live Execution (`/execute-lab`)**: Read and follow the `/execute-lab` skill (`SKILL.md`) to launch the numerical staging `lab_id`, authenticate in an isolated `CLOUDSDK_CONFIG` (`CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE=false`), and verify:
   - **Infrastructure Audit**: Confirm `allow-http-https-dns-egress` (`900`), `deny-all-egress` (`1000`), and `DEPRIVILEGE` on the Default Compute SA (if `tf/iam_delegated.tf` is deployed).
   - **Negative Security Proof**: Verify as `user_0` that privilege escalation (`roles/owner`, `roles/editor`, `roles/aiplatform.user`) fails with `403 PERMISSION_DENIED`.
   - **Positive Curriculum Proof**: Execute the student commands from `instructions/en.md` (ensuring `--condition=None` is included on `gcloud projects add-iam-policy-binding` when `tf/iam_delegated.tf` is present) and confirm all curriculum tasks succeed.
3. **Phase C — Feedback Loop**: If any command fails due to a missing permission or CLI quirk during `/execute-lab`, record the finding via `record_pitfall` into `kb/pitfalls.yaml` and update the hardened lab branch.

---


## 🎫 Automated QA & Architect Staging Tickets (Uniform Format & Two-Track Routing)

> [!NOTE]
> Do NOT create GitHub Issues tickets or GitHub PRs unless the user explicitly requests a "rollout", "QA testing", or batch PR.
> **NEVER post batch PR tables, `/execute-lab` logs, or granular lab comments to the executive Milestone ticket `SEC-100` (`[Project Phase] Apply Hardening to all sandboxes`)**. `SEC-100` is strictly for high-level project milestones for management visibility. Always post test reports and PR links on the individual child tickets only.

When requested for a lab hardening rollout, determine the lab's **Verification Track** and create a uniformly formatted child ticket:

### 1. Two-Track QA Routing (`/execute-lab` Bypass vs. Console UI QA)
* **Track 1 — Auto-Verify & Bypass QA Team (`qa-track:cli-auto-verify`)**:
  - **Criteria**: Labs where student steps are CLI/script-driven (`gcloud`, `bq`, `kubectl`, `terraform`, `curl`) or Agent Platform Workbench `.ipynb` notebooks where `/execute-lab` + Activity Tracking (`/assessments/run_step.json`) can verify provisioning, permissions, and grading end-to-end.
  - **Action**: Run `/execute-lab` + `/assessments/run_step.json` $\rightarrow$ post the verification report to the child ticket $\rightarrow$ assign the child ticket to **`${USER:-znoah}@google.com`** (current author/reviewer) $\rightarrow$ **merge the PR directly to `main`** for immediate re-publishing (bypassing `training-qa-testers@google.com`).
* **Track 2 — Human Console UI QA (`qa-track:console-ui-qa`)**:
  - **Criteria**: Labs requiring human browser click-paths inside the Google Cloud Console UI (e.g. SCC Console wizards, Gemini in BigQuery SQL Studio UI, Agent Platform Studio prompt UI, Looker Studio) that `/execute-lab` cannot drive via CLI.
  - **Action**: Run `/execute-lab` first-pass to verify clean staging startup (`startup_script_state == "complete"`) $\rightarrow$ post the pre-flight report to the child ticket $\rightarrow$ assign the child ticket (`P1`) to **`training-qa-testers@google.com`**.

### 2. Uniform Child GitHub Issues Ticket Specification
- **Component ID**: `1939024` (Lab Architects team project)
- **Title (STRICT UNIFORM FORMAT)**: `[Security Hardening] <lab-slug>`
- **Issue Type**: `PROCESS`
- **Priority / Severity**: `P1` / `S1`
- **Assignee**:
  - `${USER:-znoah}@google.com` (current author/reviewer for `qa-track:cli-auto-verify` labs verified via `/execute-lab`)
  - `training-qa-testers@google.com` (for `qa-track:console-ui-qa` labs requiring manual Console click-through)
- **Parent Initiative**: `SEC-100` ([Project Phase] Apply Hardening to all sandboxes)
- **Parent Linking**:
  ```bash
  gh issue add-issue-parent --issue-id <CHILD_ID> --parent-id SEC-100
  ```

### 3. Ticket Body Template
```markdown
### 🧪 QA Testing Scope & Guidelines (Security Hardening Review)
This lab has been hardened with least-privilege IAM and network egress firewalls to prevent fraud and abuse.

* **Parent Initiative**: http://SEC-100
* **Repository**: example-org/cloud-sandboxes
* **Pull Request**: {pr_url}
* **Staging Lab URL**: https://gcpstaging.sandbox-platform.com/authoring/labs/{staging_lab_id}
* **Rollout Campaign**: `cloud-sandbox-security-hardening`
* **Verification Track**: `{qa_track}`

**Changes Made:**
- **IAM Scoping:** Removed broad roles (`roles/owner` / `roles/editor`); added {roles_list}.
- **Network Egress:** Restricted outbound traffic to ports 80, 443, 53, 123 (`tf/secure_network.tf`).
- **Remediation Details:** {patches_applied}.

**STRICT QA TESTING BOUNDARY:**
* **What to test for**: Walk through the Console steps and click the Activity Tracking ("Check my progress") buttons to confirm our new IAM roles and firewall rules do **not** cause:
  1. `403 PERMISSION_DENIED` errors on student commands or Console actions.
  2. Network timeouts on required downloads (e.g. `pip install`, `apt`, `curl`).
  *(No editorial review needed.)*
* **Baseline Defect Decoupling**: If the lab fails due to an existing baseline issue unrelated to permissions/network (e.g. `404 Model Not Found` on an older Gemini model, deprecated OS image, or console UI rename):
  - **Do NOT block this security PR.**
  - Ignore baseline defects (or file a separate bug for the lab owner) and approve this security ticket so we can merge the protection.
* **Fixes**: If a step hits a `403 PERMISSION_DENIED` error, feel free to add the missing role to the PR if comfortable, or drop the exact error message in a ticket comment for remediation.
```

---

## 🏷️ Git Commit, PR Creation & GitHub Issues Tagging Standards

Per the **[Agentic Mass Update Playbook](https://https://github.com/zachnoah89/agentic/blob/main/README.md)**, all PRs and tickets must adhere to standardized naming, labelling, and tagging (identical to `/implement-ddm` and `/migrate-genai-tier`):

* **Branch Name**: `feat/hardening-<lab-slug>`
* **Commit Message**:
  ```text
  feat(security): harden <lab-slug> least-privilege IAM and egress network

  BUG=<child_bug_id>
  ```
* **Mandatory PR Labels**:
  * `cloud-sandbox-security-hardening` (Campaign Tag)
  * `bug:SEC-100` (Parent Tracking Initiative)
  * `security` (Domain label)
  * `anti-abuse` (Hardening tag)
* **Operational Rationale**:
  1. **Fleet-Wide Search & Triage**: Enables bulk-querying, filtering, and reporting on all security rollout PRs across GitHub using `gh pr list --label cloud-sandbox-security-hardening`.
  2. **Batch Rollback Safety**: Directly connects with `scripts/maintenance/batch_revert.py --tag cloud-sandbox-security-hardening` for automated emergency rollback across both open and merged PRs if unexpected platform regressions occur.

### PR Creation Command:
```bash
gh pr create \
  --title "feat(security): harden <lab-slug> least-privilege IAM and egress network" \
  --body "### Summary of Changes
- Stripped over-privileged roles (\`roles/owner\`, \`roles/editor\`).
- Scoped minimal IAM roles: \`{roles_list}\`.
- Applied outbound network egress firewall (\`ports 80, 443, 53, 123\`).
- Enforced IMDSv2 and clean mustache syntax.
- Pre-merge compliance gate: \`validate_pre_merge\` passed (\`PASS\`).

**Tracking Issue**: [b/<CHILD_BUG_ID>](http://b/<CHILD_BUG_ID>)
**Parent Initiative**: [SEC-100](http://SEC-100) ([Project Phase] Apply Hardening to all sandboxes)
**Rollout Campaign**: \`cloud-sandbox-security-hardening\`
**Assignee**: \`training-qa-testers@google.com\`" \
  --label "cloud-sandbox-security-hardening" \
  --label "bug:SEC-100" \
  --label "security" \
  --label "anti-abuse"
```

### Batch Rollback & Emergency Triage:
If an unexpected issue arises post-merge or during rollout, execute an automated batch revert using the campaign tag:
```bash
# Preview actions without modifying state:
python3 scripts/maintenance/batch_revert.py --tag cloud-sandbox-security-hardening --dry-run

# Revert all open and merged PRs under the campaign:
python3 scripts/maintenance/batch_revert.py --tag cloud-sandbox-security-hardening --mode all --reason "Rollback requested for cloud-sandbox-security-hardening rollout"
```

---

## 🔄 Continuous Learning: Capturing Testing Feedback (`record_pitfall`)

When a lab fails during manual QA or automated staging testing (e.g. an assessment check fails due to an unexpected missing permission or API quirk), capture the finding into the shared knowledge base so all future hardening runs and team members automatically benefit.

### 1. How to Record via Claude Code / Gemini CLI (Chat Prompting)
If using Claude Code / Gemini CLI with the `cloud-sandbox-security` plugin enabled, prompt the agent:
```text
QA testing on <lab-slug> failed:
Task #<N> (assessment check <name>) failed with error: "<error message / permission denied>".
The assessment script requires <required_role> to <cause of failure>.
Please record this pitfall and update <lab-slug> with the required role.
```
The agent will call `record_pitfall(...)`, append the verified entry to `kb/pitfalls.yaml`, and apply the fix.

### 2. How to Record via CLI (For QA Testers without Claude Code / Gemini CLI)
Testers in Cloud Shell or local terminal can run the CLI helper directly:
```bash
python3 .agent/plugins/cloud-sandbox-security/scripts/record_pitfall.py \
  --lab <lab-slug> \
  --symptom "Assessment check 3 fails with 403 Forbidden" \
  --cause "Assessment script probes instance metadata via compute API" \
  --fix "Grant roles/compute.instanceAdmin.v1 in sandbox.yaml" \
  --role "roles/compute.instanceAdmin.v1" \
  --author "$USER"
```

### 3. Review & Git Sync
After recording:
1. Verify the addition: `git diff .agent/plugins/cloud-sandbox-security/kb/pitfalls.yaml`
2. Commit and PR: `git commit -am "kb(pitfalls): record <pitfall-id> for <lab-slug>"`
