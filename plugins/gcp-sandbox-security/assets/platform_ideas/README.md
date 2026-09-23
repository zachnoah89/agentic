# Platform Discussion Starters & Exploratory Ideas

> [!NOTE]
> **Not for Lab-Level Deployment**: The templates in this directory are exploratory concepts, reference snippets, and discussion starters for future syncs with Cloud Sandbox Platform Platform, Navy Infrastructure, and Abuse teams. They represent controls that require Organization/Folder Admin privileges and cannot be executed directly in student lab Terraform.

## Contents
* `vpc_sc_token_exfil_lockdown.tf.template`: **Proposal 1 (Primary Lead-In) — Targeted VPC Service Controls (VPC-SC) on `sandbox-platform-terminal-vms-prod-00` (`student-vms` VPC) + Scoped `user_0` IAM Policy (`SEC-001`)** — Because every managed_ide_proxy VM in production runs inside one single GCP project (`sandbox-platform-terminal-vms-prod-00`) and one single VPC network (`//compute.googleapis.com/projects/sandbox-platform-terminal-vms-prod-00/global/networks/student-vms`, `172.16.0.0/12`, with 50 static regional Cloud NAT IPs per region), enclosing managed_ide_proxy `genai_sandbox` projects in a Service Perimeter allowlisting `student-vms` + the Student VPC (while scoping `{gcp_project}@{gcp_project}.iam.gserviceaccount.com` to `user_0`'s declared IAM roles) requires **zero changes** to `servicer.py` or Docker containers and immediately blocks external botnets from using stolen `keys.json`, `ya29...` tokens (`gcloud auth print-access-token`), or `user_0` logins (`403 VPC_SERVICE_CONTROLS`).
* `managed_ide_workload_identity.tf.template`: **Proposals 2 & 3 (Retiring `/home/user/keys.json`) — Host-VM Short-Lived Token Proxy (`access_token_file`) or Per-Session Workload Identity Federation (`sts.googleapis.com` bound to `vm_name`)** — Preserves the 1,830-VM warm GCE pool in `sandbox-platform-terminal-vms-prod-00` (where pooled VMs share static VM-attached SAs like `student-theia@`) while eliminating `iam.googleapis.com/serviceAccountKeys.create` (`/home/user/keys.json`) and removing the `ide-provisioner@` exemption from the `genai_sandbox` IAM Deny Policy (`Policy-Deny-SA-Keys`).
* `org_policy_sa_keys.tf.template`: Reference concept for service account key blocking (note: Navy implemented this via `google_iam_deny_policy` on `genai_sandbox` to allow exception principals).
* `org_policy_machine_types.tf.template`: Reference concept for machine type scoping (currently enforced via Navy Variant Base Types and quota caps).
* `org_policy_cloud_run_egress.tf.template`: Reference concept for serverless egress routing.

---

## Architectural Comparison: Proposals 1, 2, & 3 (`SEC-001`)

| Security Goal / Engineering Dimension | Proposal 1 (Lead-In): Targeted VPC-SC (`student-vms` VPC) + Scoped `user_0` IAM (`vpc_sc_token_exfil_lockdown.tf.template`) | Proposal 2: Host-VM Token Proxy (`access_token_file` + Metadata Proxy) (`managed_ide_workload_identity.tf.template`) | Proposal 3: Per-Session WIF (`sts.googleapis.com` bound to `vm_name`) (`managed_ide_workload_identity.tf.template`) |
| :--- | :--- | :--- | :--- |
| **Blocks external botnets using stolen `keys.json`, `ya29...` tokens (`print-access-token`), or `user_0` logins** | ✅ **YES** (`403 VPC_SERVICE_CONTROLS` from any IP outside `student-vms` / Student VPC) | ❌ No (15–30 min token works externally unless paired with Proposal 1) | ❌ No (15–30 min token works externally unless paired with Proposal 1) |
| **Requires changes to Managed Web IDE Proxy `servicer.py` or Docker containers** | ✅ **ZERO changes** to `servicer.py` or Docker containers | Low/Medium (`servicer.py` `_get_authenticate_command` + `linux.sh`) | Medium/High (Requires OIDC JWT issuer in `ManagedWebIDEServicer`) |
| **Eliminates `/home/user/keys.json` on disk & drops `ide-provisioner@` Deny exemption (`Policy-Deny-SA-Keys`)** | ❌ No (`keys.json` is rendered useless externally; pair with Proposal 2 to delete file) | ✅ **YES** (No JSON key ever created; uses `generateAccessToken`) | ✅ **YES** (No private key ever created; uses STS token exchange) |
| **Stops privilege escalation inside container (e.g., GPU creation)** | ✅ **YES** (Via Step 1B scoping SA to `user_0` IAM roles) | ✅ **YES** (When paired with scoped `user_0` IAM roles) | ✅ **YES** (When paired with scoped `user_0` IAM roles) |
| **Preserves 1,830-VM warm pool in `sandbox-platform-terminal-vms-prod-00`** | ✅ **YES** (100% transparent to warm pool) | ✅ **YES** (Zero VM restarts required) | ✅ **YES** (Zero VM restarts required) |

For the full context and discussion roadmap, see:
* [Managed Web IDE Proxy Security & Keyless Architecture Proposal (SEC-001)](https://https://github.com/zachnoah89/agentic/blob/main/README.md?tab=t.0)
* [`kb/org_policies.yaml`](../../kb/org_policies.yaml)
* [`references/platform_security_roadmap.md`](../../references/platform_security_roadmap.md)
