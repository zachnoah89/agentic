# Implement `genai_sandbox` Fleet Variant

Automated migration skill and verification tooling to update Generative AI and LLM labs across Cloud Sandbox Platform catalogs to the **`genai_sandbox`** fleet variant.

---

## 📌 Initiative & Context

* **Parent Tracking Bug**: **[SEC-102](https://gh issue.corp.google.com/issues/SEC-102)** (`[LA Project 2026] Fleet Migration: Migrate LLM Labs to genai_sandbox Variant`)
* **Related Issues**: [SEC-105](https://gh issue.corp.google.com/issues/525042135) (Fleet Implementation), [SEC-105](https://gh issue.corp.google.com/issues/545187512) (Recaptcha Shift), [SEC-105](https://gh issue.corp.google.com/issues/525392026)
* **Design & Strategy**: Structured per the [Agentic Mass Update Playbook](https://https://github.com/zachnoah89/agentic/blob/main/README.md).

---

## 📂 Skill Architecture

```
.agent/plugins/cloud-sandbox-security/skills/migrate-genai-tier/
├── SKILL.md                              # Agent skill directives, workflow & negative guardrails
├── README.md                             # Documentation and CLI references
├── assets/
│   ├── sample_fleet_inventory.csv        # Master Inventory tracking status across catalog
│   └── sa_key_remediation_guide.md       # SA key pre-provisioning & IAM hardening guide
└── scripts/
    ├── audit_genai_sandbox.py                  # Standalone pre/post-flight validator CLI
    ├── batch_migrate_genai_fleet.py        # Automated batch migration & PR creation CLI
    └── generate_genai_inventory.py         # Catalog scanner & inventory generator
```

---

## 🛠️ CLI Utilities

### 1. Audit Single Lab Directory
```bash
python3 scripts/audit_genai_sandbox.py /path/to/cloud-sandboxes/labs/<LAB_SLUG>
```

### 2. Audit Entire Repository
```bash
python3 scripts/audit_genai_sandbox.py --all-labs /path/to/cloud-sandboxes/labs
```

### 3. Regenerate Master Inventory CSV
```bash
python3 scripts/generate_genai_inventory.py \
    --labs-dir /path/to/cloud-sandboxes/labs \
    --output-csv assets/sample_fleet_inventory.csv
```

### 4. Automated Batch Migration
```bash
python3 scripts/batch_migrate_genai_fleet.py --slugs <SLUG_1> <SLUG_2>
# Or migrate next batch of identified LLM labs:
python3 scripts/batch_migrate_genai_fleet.py --all --limit 10
```

---

## 🔒 Security & Policy Highlights

The `genai_sandbox` fleet variant enforces a folder-level Google IAM Deny Policy on **`iam.googleapis.com/serviceAccountKeys.create`** for student sessions:
* **Allowed**: Full access to Agent Platform Foundation Models, Gemini API, AI Studio, Prompt Gallery, and Application Default Credentials (ADC).
* **Blocked**: Manual `gcloud iam service-accounts keys create` commands (preventing token theft and scraping bot abuse).
* **Pre-Provisioning**: Keys required for lab runtime must be pre-provisioned via Terraform (`google_service_account_key`) since Navy backend service accounts are exempt from the deny policy.
