---
name: migrate-genai-tier
description: >-
  Use this skill when asked to migrate a lab to the genai_sandbox fleet variant,
  mitigate service account key abuse on Generative AI labs, or update
  sandbox.yaml project resources for labs using Gemini, Agent Platform Studio,
  Agent Builder, Reasoning Engine, PaLM, or GenAI SDKs, even if the user
  does not explicitly mention "genai_sandbox" or "fleet variant". Audits the lab
  directory with audit_genai_sandbox.py to verify absence of manual service account
  keys and surgically sets policy_tier: genai_sandbox on gcp_project resources.
  Do NOT use for editing markdown instructions or updating legacy predictive
  ML labs that require manual service account keys without a Terraform workaround.
---

# Migrate Lab to `genai_sandbox` Fleet Variant

This skill guides the agent to migrate Google Cloud ephemeral cloud sandboxes utilizing Generative AI (Gemini, Agent Platform Studio, Agent Builder, Model Garden, PaLM/Bison, GenAI SDKs) to the **`genai_sandbox`** fleet variant in `sandbox.yaml`.

---

## 1. Background & Security Rationale

Under the hood ([SEC-105](http://SEC-105) and [SEC-105](http://SEC-105)), the **`genai_sandbox`** fleet variant provisions student environments inside dedicated GCP folders governed by an authoritative Google IAM Deny Policy:

$$\text{Denied Permission: } \texttt{iam.googleapis.com/serviceAccountKeys.create}$$

### Why this migration is required:
1. **Shifting reCAPTCHA Friction**: Shifting the QR Code / Modac reCAPTCHA from general user signup to *only* when a broad-reach learner launches an LLM lab ([SEC-105](http://SEC-105)).
2. **Abuse Mitigation**: Prevents malicious actors from exfiltrating JSON service account keys to run external scraping/LLM bots against Gemini and Agent Platform APIs using Cloud Sandbox Platform billing.
3. **Backend Exemption & ManagedWebIDE Warning ([SEC-001](http://SEC-001))**: Because Cloud Sandbox Platform internal orchestrator service accounts (`ide-provisioner@`) are exempted from the `genai_sandbox` IAM Deny Policy (`Policy-Deny-SA-Keys`), any ManagedWebIDE resource (`ide`, `cloud_terminal`, `looker_instance`, `jupyter_notebook`) will mint and mount `/home/user/keys.json` in `sandbox-platform-prod`, bypassing the deny policy. Therefore, **ManagedWebIDE labs MUST NEVER be migrated to `policy_tier: genai_sandbox`**.

---

## 2. Mandatory Negative Guardrails

> [!IMPORTANT]
> **Strict Single-Surface Scope & Exfiltration Guardrails**:
> 1. **Do NOT touch markdown instructions** (`instructions/en.md` or localized `instructions/*.html`). Do NOT update `Manual Last Updated` or `Lab Last Tested` timestamps. The diff must remain strictly surgical in `sandbox.yaml`.
> 2. **Do NOT alter `type: gcp_user` variants**: Leave `variant: default` / `gcp_only` / `extra` untouched on user resources. Only `type: gcp_project` is updated to `policy_tier: genai_sandbox`.
> 3. **NEVER migrate ManagedWebIDE (`ide`, `cloud_terminal`, `looker_instance`, `jupyter_notebook`) labs to `policy_tier: genai_sandbox` (`managed_ide_proxy_EXCLUDED` / [SEC-001](http://SEC-001))**: Doing so exposes `/home/user/keys.json` with LLM access outside the student VPC.
> 4. **Do NOT migrate labs that create manual SA keys (`REQUIRES_WORKAROUND_SA_KEY`) or mint `google_service_account_key` on SAs with `roles/aiplatform.user`, `roles/editor`, or `roles/owner`**: LLM labs must use VM-attached Service Accounts (IMDSv2) inside `tf/secure_network.tf` or Application Default Credentials (ADC), never exportable JSON keys.

---

## 3. Step-by-Step Migration Protocol

### Step 1: Preflight Audit
Run the automated validator against the lab directory:
```bash
python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/audit_genai_sandbox.py labs/<LAB_SLUG>
```

* **If `STATUS: COMPLIANT`** $\rightarrow$ Lab is already configured with `policy_tier: genai_sandbox`. No changes needed.
* **If `STATUS: managed_ide_proxy_EXCLUDED`** $\rightarrow$ **STOP.** Do NOT apply `genai_sandbox` (`SEC-001`).
* **If `STATUS: REQUIRES_WORKAROUND_SA_KEY`** $\rightarrow$ **STOP.** Do NOT apply `genai_sandbox` yet. Refactor to VM-attached SA (IMDSv2) or ADC first.
* **If `STATUS: NEEDS_MIGRATION`** $\rightarrow$ Proceed to Step 2.
* **If `STATUS: NON_LLM_LAB`** $\rightarrow$ Verify why the lab was targeted. If no GenAI features are used, leave on standard `variant: standard_sandbox`.

---

### Step 2: Refactor `sandbox.yaml`

Inspect `sandbox.yaml` under `environment.resources`:

#### Before (Standard / Default Variant):
```yaml
environment:
  resources:
    - type: gcp_project
      id: project_0
      variant: standard_sandbox
```
*(Or missing `variant:` key, which defaults to `standard_sandbox`).*

#### After (`genai_sandbox` Fleet Variant):
```yaml
environment:
  resources:
    - type: gcp_project
      id: project_0
      policy_tier: genai_sandbox
```

#### Multi-Project Considerations:
* If a lab has multiple GCP projects (e.g. `project_0` and `project_1`), apply `policy_tier: genai_sandbox` to any project resource where Agent Platform, Gemini, or GenAI services are invoked.
* Preserve all other existing resource keys: `custom_properties`, `allowed_locations`, and IAM role bindings.

---

### Step 3: Verification & Post-Flight Linting

1. Verify YAML syntax and indentation:
   ```bash
   python3 -c 'import yaml; yaml.safe_load(open("labs/<LAB_SLUG>/sandbox.yaml"))'
   ```
2. Re-run `audit_genai_sandbox.py` to confirm compliance:
   ```bash
   python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/audit_genai_sandbox.py labs/<LAB_SLUG>
   ```
   *Output must show: `Status: COMPLIANT` and `Compliant: ✅ YES`.*

---

### Step 4: Create Dedicated Child GitHub Issues Ticket

For every lab migrated, create a dedicated child tracking ticket under the Lab Architects project component and link it as a sub-task to the parent initiative:

* **Component ID**: `1939024` (Lab Architects team project)
* **Title**: `[Fleet Migration] Migrate <LAB_SLUG> to genai_sandbox variant`
* **Assignee**: `${USER:-znoah}@google.com` (current author/reviewer)
* **Status**: `ASSIGNED`
* **Priority / Severity**: `P3` / `S3`
* **Parent Issue ID**: `SEC-102` (Linked via `gh issue add-issue-parent --issue-id <CHILD_ID> --parent-id SEC-102`)

---

## 4. Git Commit, PR Creation & Standardized Tagging

Per the **[Agentic Mass Update Playbook](https://https://github.com/zachnoah89/agentic/blob/main/README.md)**, all PRs must adhere to standardized naming, labelling, and tagging:

* **Branch Name**: `feat/gcp-llm-fleet-<LAB_SLUG>`
* **Commit Message**: `feat(fleet): migrate <LAB_SLUG> to genai_sandbox fleet variant`
* **Mandatory PR Labels**:
  * `gcp-llm-fleet-rollout` (Campaign Tag)
  * `bug:SEC-102` (Parent Tracking Initiative)
  * `variant:genai_sandbox` (Target Architecture)
* **Operational Rationale**:
  1. **Fleet-Wide Search & Triage**: Enables bulk-querying and filtering all rollout PRs across GitHub using `gh pr list --label gcp-llm-fleet-rollout`.
  2. **Batch Rollback Safety**: Directly connects with `scripts/maintenance/batch_revert.py --tag gcp-llm-fleet-rollout` for automated emergency rollback across both open and merged PRs.

### PR Creation Command:
```bash
gh pr create \
  --title "feat(fleet): migrate <LAB_SLUG> to genai_sandbox fleet variant" \
  --body "### Summary of Changes
- Migrated \`sandbox.yaml\` \`gcp_project\` resource(s) to \`policy_tier: genai_sandbox\`.
- Audited for absence of manual service account key creation.
- Preflight validation: \`audit_genai_sandbox.py\` passed (Status: COMPLIANT).

**Tracking Issue**: [b/<CHILD_BUG_ID>](http://b/<CHILD_BUG_ID>)
**Parent Initiative**: [SEC-102](http://SEC-102)
**Rollout Campaign**: \`gcp-llm-fleet-rollout\`
**Assignee**: \`${USER:-znoah}@google.com\`" \
  --label "gcp-llm-fleet-rollout" \
  --label "bug:SEC-102" \
  --label "variant:genai_sandbox"
```

---

## 5. Automated Batch Migration Execution

To migrate multiple catalog labs in batch with automated child ticket creation, standardized PR tagging, and inventory updates:

```bash
# Migrate a specific batch of labs:
python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/batch_migrate_genai_fleet.py --slugs sandbox-demo-getting-started-with-agent-platform-studio sandbox-demo-prompt-design-in-agent-platform-studio

# Or migrate all identified catalog LLM labs in batches:
python3 .agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/scripts/batch_migrate_genai_fleet.py --all --limit 10
```

---

## 6. Batch Rollback & Emergency Triage

If an unexpected issue arises post-merge or during rollout, execute an automated batch revert using the campaign tag:

```bash
# Preview actions without modifying state:
python3 scripts/maintenance/batch_revert.py --tag gcp-llm-fleet-rollout --dry-run

# Revert all open and merged PRs under the campaign:
python3 scripts/maintenance/batch_revert.py --tag gcp-llm-fleet-rollout --mode all --reason "Rollback requested for genai_sandbox rollout"
```


