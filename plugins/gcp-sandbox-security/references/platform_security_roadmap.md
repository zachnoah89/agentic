# Cloud Lab Platform Organization-Level Security Knowledge Base & Platform Roadmap

## Overview & Architectural Scope

This document defines the boundary between **Lab-Level Controls** (authored in `sandbox.yaml` and lab `tf/`) and **Platform/Organization-Level Controls** (managed by Cloud Lab Platform, Navy Infrastructure, and Cloud Abuse teams).

It serves as the technical ground truth for Lab Architects and a communication hub for discussions with Cloud Lab Platform and Infrastructure engineering teams.

---

## 1. The Core Architectural Principle

```
+-----------------------------------------------------------------------------+
|                        CLOUD LAB PLATFORM / NAVY LAYER                      |
| (Navy Infrastructure, Shared Org Policies, IAM Deny Policies, Quota Engine)  |
|                                                                             |
|  * Folder-Level IAM Deny Policies (e.g. Service Account Key Blocking)        |
|  * Hierarchical Org Security Policies (Egress Denials to C2/Discord)        |
|  * Project Variant Reputation & Base Machine Type Enforcement               |
|  * Centralized Producer Quotas (Token per minute ceilings, 0 GPU caps)      |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                          GRANULAR LAB AUTHORING LAYER                       |
|                 (Lab Architect Scope: sandbox.yaml & tf/)                  |
|                                                                             |
|  * Scoped IAM Roles for user_0 (NEVER roles/owner or roles/editor)          |
|  * Isolated VPC & Egress Firewalls (secure_network.tf: 80, 443, 53, 123)    |
|  * Compute Instance Metadata (IMDSv2: disable-legacy-endpoints = TRUE)      |
|  * Pre-provisioned Service Account Keys for 3rd-party student integrations  |
+-----------------------------------------------------------------------------+
```

### Why Org Policies Do Not Belong in Lab Terraform
Terraform in ephemeral cloud sandboxes runs under the authority of tenant projects and provisioned student identities. These identities **do not have `roles/orgpolicy.policyAdmin`** or Access Context Manager administration privileges. Any attempt to declare `google_org_policy_policy` or `google_access_context_manager_*` inside a lab's `tf/` directory will result in a hard `403 PERMISSION_DENIED` during `terraform apply`.

---

## 2. Technical Audit of Existing Org Policy Assets

### A. Service Account Key Creation
* **Lab Asset**: `assets/org_policy_sa_keys.tf.template` (Attempts boolean `iam.disableServiceAccountKeyCreation`).
* **Technical Reality**:
  * Navy Engineering originally attempted this boolean Org Policy (`modules/disable_service_account_key_creation`), but it caused severe regressions: *"This approach prevented navy from creating required service account keys."*
  * Org Policies do not support exemption principals. It blocked Navy's own administrative automation (`ide-provisioner@` and `gke-services-cluster@`) from generating necessary provisioning keys.
* **The Working Solution (Policy-Deny-SA-Keys)**:
  * Replaced with a **Google Cloud IAM Deny Policy** (`modules/deny_service_account_key_creation`) at the **Folder Level** on `genai_sandbox` (`folders/970562261276` prod, `folders/1089932235197` staging).
  * Denies `iam.googleapis.com/serviceAccountKeys.create` to `principalSet://goog/public:all` while explicitly exempting `ide_provisioner` and `gke-services-cluster`.
* **The `ide-provisioner@` Exemption Paradox (`SEC-001` — Managed Web IDE Proxy Exfiltration)**:
  * Because `ide-provisioner@sandbox-platform-prod.iam.gserviceaccount.com` is exempted from the `genai_sandbox` IAM Deny Policy, any lab declaring a **Managed Web IDE Proxy** resource (`type: ide`, `type: cloud_terminal`, `type: looker_instance`, `type: jupyter_notebook`) triggers `ide_proxy/provisioner.py` (`ide-provisioner@`) to mint a static JSON SA key and mount it inside the container at `/home/user/keys.json`.
  * Furthermore, Managed Web IDE Proxy containers run in Cloud Sandbox Platform' central GKE cluster (`sandbox-platform-prod`), **not** inside the student's VPC (`tf/secure_network.tf`), and Agent Platform (`https://aiplatform.googleapis.com`) is a Google Cloud Control-Plane API reachable from any IP on the public internet. Once `/home/user/keys.json` is copied out of the browser IDE, `tf/secure_network.tf` is 100% bypassed.
  * **Architectural Rule**: NEVER deploy Managed Web IDE Proxy (`ide`, `cloud_terminal`, `looker_instance`, `jupyter_notebook`) on `policy_tier: genai_sandbox` (or `gcp_medium_extra` in public catalogs).
* **The Active Gap**:
  * This Deny Policy is currently bound **only** to the `genai_sandbox` folder.
  * Folders like `standard_sandbox`, `gcpondemand`, and `gcp_low_extra` do **not** have it enabled.

### B. Machine Types & GPU Mining Abuse
* **Lab Asset**: `assets/org_policy_machine_types.tf.template` (Attempts `compute.restrictMachineTypes`).
* **Technical Reality**:
  * Navy already enforces this at the platform layer via **Project Variants and Reputations**.
  * `gcp_very_low_base`, `standard_sandbox`, `genai_sandbox`, and `gcp_low_extra` are restricted to "Base Types" (max 6 VMs, 24 cores/region, 0 GPUs, disallowed `custom-6-49152` and `custom-6-39936`).
  * In `cloud/training/sandbox-platform/abuse/scripts/sandbox-platform_custom_quota.yaml`, GPU training and serving quotas are pinned to `0`.

### C. Cloud Run Egress
* **Lab Asset**: `assets/org_policy_cloud_run_egress.tf.template` (Attempts `run.allowedVPCEgress = all-traffic`).
* **Technical Reality**:
  * If applied globally at the organization or folder level, it breaks all serverless labs that do not spin up Serverless VPC Access connectors.
  * Managed at platform level via strict instance ceilings (`max_instances_for_limited_instance_projects = 32`). When a specific lab needs VPC egress, it should be set directly on `google_cloud_run_v2_service.vpc_access` in lab Terraform.

### D. IMDSv2 Enforcement
* **Lab Asset**: `assets/disable_imds_v1.tf.template` (Sets `disable-legacy-endpoints = "TRUE"`).
* **Technical Reality**:
  * **100% valid, functional, and necessary at the lab level** on `google_compute_instance`.
  * Also an ideal candidate for Navy to apply globally via `constraints/compute.disableLegacyEndpoints` at the `Navy Projects` folder level.

### E. The Reality of VPC Service Controls (VPC-SC) vs. Targeted Headless Perimeters
* **Lab Asset**: `assets/platform_ideas/vpc_sc_token_exfil_lockdown.tf.template`
* **Full Proposal Doc**: [Managed Web IDE Proxy Security & Keyless Architecture Proposal (`SEC-001`)](https://https://github.com/zachnoah89/agentic/blob/main/README.md?tab=t.0)
* **The Theory**: Enclose the student project in a Service Perimeter around `aiplatform.googleapis.com`, `generativelanguage.googleapis.com`, and `storage.googleapis.com`.
* **Why VPC-SC Has Friction on General Cloud Console sandboxes**:
  1. **Dynamic Student Egress IPs**: Students access the Google Cloud Console from arbitrary home, enterprise, and mobile networks worldwide. A perimeter blocking non-private API calls blocks the Cloud Console UI unless wide-open access levels are defined.
  2. **Console UI Failures**: The web UI makes background calls to Model Garden, Cloud Logging, and metadata APIs that fail cryptically inside perimeters.
  3. **External Dataset Ingress**: Blocks pulling model weights and datasets from public GCS buckets, HuggingFace, or external APIs.
* **Where VPC-SC IS Uniquely Effective (Proposal 1 Lead-In: Targeted Managed Web IDE Proxy `student-vms` VPC + Off-Platform Token Lockdown)**:
  * Inspection of `student_networks.tf` and `managed_ide_instance_prod_00/main.tf` reveals that **every managed_ide_proxy VM in production** (`cloud_terminal_pool_size = 1000`, `theia_pool_size = 500`, `looker_instance_pool_size = 300`, `jupyter_notebook_pool_size = 30`) runs inside one single GCP project (`sandbox-platform-terminal-vms-prod-00`) and one single VPC network (`//compute.googleapis.com/projects/sandbox-platform-terminal-vms-prod-00/global/networks/student-vms`, `172.16.0.0/12`, with 50 static regional Cloud NAT IPs per region).
  * Therefore, placing managed_ide_proxy `genai_sandbox` projects in a VPC-SC perimeter with an Access Level allowing **only `sandbox-platform-terminal-vms-prod-00` (`student-vms` VPC + regional NAT CIDRs) and the Student VPC** (combined with scoping `{gcp_project}@{gcp_project}.iam.gserviceaccount.com` to `user_0`'s declared IAM roles) requires **ZERO changes** to `servicer.py` or Docker containers and immediately blocks external botnets from using stolen `keys.json`, `ya29...` tokens (`gcloud auth print-access-token`), or `user_0` logins (`403 VPC_SERVICE_CONTROLS`).

---

## 3. Platform Discussion Topics & Exploratory Engineering Ideas

The following concepts are exploratory discussion points and collaborative ideas to review with Cloud Sandbox Platform Platform, Navy Infrastructure, and Abuse Engineering teams:

### Topic 1: Exploring Expansion of IAM Deny SA Key Creation to All Low-Rep Folders (Priority: P1)
* **Target File**: `configs/cloud/gong/services/sandbox-platform_infrastructure/envs/services_prod/navy_shared/org_policy.tf`
* **Exploratory Concept**: Evaluate attaching `module.deny_service_account_key_creation` to `local.low_rep_folders` (`standard_sandbox`, `gcpondemand`, `gcp_low_extra`, `gcp_event`, `gcpedu`) instead of only `genai_sandbox`.
* **Potential Impact**: Could eliminate static service account key exfiltration across 1,000+ non-LLM catalog labs without touching individual lab repositories.

### Topic 2: Evaluating Global IMDSv2 Enforcement via Org Policy (Priority: P1)
* **Target**: Folder `folders/365352270458` (`Navy Projects`).
* **Constraint**: `constraints/compute.disableLegacyEndpoints = TRUE`.
* **Potential Impact**: Shuts down Server-Side Request Forgery (SSRF) credential harvesting across all VM-based labs platform-wide.

### Topic 3: Assessing Restrictions on Transit VPC Peering (Priority: P2)
* **Target**: Folder `folders/365352270458` (`Navy Projects`).
* **Constraint**: `constraints/compute.restrictVpcPeering`.
* **Potential Impact**: Prevents students from configuring VPC peering to external adversary networks to bypass NAT logging or egress firewalls.

### Topic 4: Proactive Disablement of Crypto & Web3 APIs (Priority: P2)
* **Target**: `local.permanently_denied_services` in `navy_shared/org_policy.tf`.
* **Service**: `blockchainnodeengine.googleapis.com`.
* **Potential Impact**: Proactively eliminates crypto-mining and blockchain node abuse vectors.

### Topic 5: Reviewing Token Impersonation Boundaries on Management Identities (Priority: P2)
* **Mechanism**: `google_iam_deny_policy`.
* **Denied Permissions**: `iam.googleapis.com/serviceAccounts.getAccessToken`, `iam.googleapis.com/serviceAccounts.signBlob`.
* **Potential Impact**: Prevents learners from minting access tokens for platform-managed service accounts.

### Topic 6: Proposal 1 (Main Lead-In) — Targeted VPC-SC Perimeter on `sandbox-platform-terminal-vms-prod-00` (`student-vms` VPC) + Scoped `user_0` IAM Policy (Priority: P1)
* **Reference Template**: `assets/platform_ideas/vpc_sc_token_exfil_lockdown.tf.template`
* **Mechanism**: `google_access_context_manager_service_perimeter` + `google_access_context_manager_access_level` + scoped `{gcp_project}@` SA roles.
* **Exploratory Concept**: Allowlist `//compute.googleapis.com/projects/sandbox-platform-terminal-vms-prod-00/global/networks/student-vms` (plus its 50 static regional Cloud NAT IPs per region) and the Student VPC around `aiplatform.googleapis.com`, `generativelanguage.googleapis.com`, and `storage.googleapis.com`, while scoping `{gcp_project}@{gcp_project}.iam.gserviceaccount.com` in `InitializeServiceAccount` to `user_0`'s declared IAM roles from `sandbox.yaml`.
* **Potential Impact**: Requires **zero changes** to `servicer.py` or Docker containers, keeps the 1,830-VM warm GCE pool intact, and renders stolen `keys.json` files, `ya29...` OAuth bearer tokens (`gcloud auth print-access-token`), and `user_0` credentials 100% useless outside the lab network (`403 VPC_SERVICE_CONTROLS`).

### Topic 7: Proposals 2 & 3 — Retiring `/home/user/keys.json` via Host-VM Token Proxy (`access_token_file`) or Per-Session WIF (`sts.googleapis.com` bound to `vm_name`) (Priority: P1)
* **Reference Template**: `assets/platform_ideas/managed_ide_workload_identity.tf.template`
* **Target**: `ide_proxy/provisioner.py` (`_get_authenticate_command`, L359–390) & `startup_scripts/linux.sh` in `sandbox-platform-terminal-vms-prod-00`.
* **Exploratory Concept**: Because pooled GCE VMs in `sandbox-platform-terminal-vms-prod-00` share a static VM-attached SA (`student-theia@`, `student-cloud-terminal@`), we cannot bind the VM's attached SA directly to a student project without cross-student access. Instead:
  - **Proposal 2 (Host-VM Short-Lived Token Proxy)**: The outer GCE host VM (`sandbox-platform` user, outside the unprivileged `student` Docker container) calls `iamcredentials.projects.serviceAccounts.generateAccessToken` (`15–30 min` TTL) and bind-mounts `/run/ql_auth/access_token` read-only into the container (`gcloud config set auth/access_token_file /run/ql_auth/access_token` + 1-line `iptables` redirect on `169.254.169.254` in `linux.sh`).
  - **Proposal 3 (Per-Session WIF Bound to `vm_name`)**: Central WIF Pool (`managed_ide_proxy-pool`) where `ManagedWebIDEServicer` signs a session OIDC JWT (`sub = vm_name`) and binds `roles/iam.workloadIdentityUser` on the student project SA strictly to `.../subject/<vm_name>`.
* **Potential Impact**: Eliminates `/home/user/keys.json` creation across all managed_ide_proxy labs (`SEC-001`) while preserving the 1,830-VM warm pool, and allows removing the `ide-provisioner@` exemption from the `genai_sandbox` IAM Deny Policy (`Policy-Deny-SA-Keys`).

---

## 4. Lab-Level Security Rules Summary

For Lab Architects authoring content in `cloud-sandboxes` and partner repos:

1. **NEVER grant `roles/owner` or `roles/editor`** to `user_0` in `sandbox.yaml`.
2. **Scope all student permissions** to specific resource types (e.g. `roles/aiplatform.user`, `roles/viewer`).
3. **Always deploy `secure_network.tf`** to restrict outbound egress to ports 80, 443, 53, and 123.
4. **Always set `disable-legacy-endpoints = "TRUE"`** on all `google_compute_instance` resources.
5. **Never grant `roles/iam.serviceAccountAdmin` or `roles/iam.serviceAccountUser` at project level**. Scope via `google_service_account_iam_member` in Terraform.
