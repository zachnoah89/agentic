#!/usr/bin/env python3
"""audit_genai_sandbox.py: Validates LLM usage, SA key creation, and genai_sandbox variant compliance.

Usage:
    python3 audit_genai_sandbox.py <path_to_lab_directory>
    python3 audit_genai_sandbox.py --all-labs <path_to_labs_repo_directory>
"""

import argparse
import json
import os
import re
import sys
import yaml

LLM_PATTERNS = [
    r"aiplatform\.googleapis\.com",
    r"generativelanguage\.googleapis\.com",
    r"cloudaicompanion\.googleapis\.com",
    r"vertexai\.generative_models",
    r"google\.genai\b",
    r"GenerativeModel\b",
    r"ChatModel\b",
    r"TextGenerationModel\b",
    r"CodeGenerationModel\b",
    r"TextEmbeddingModel\b",
    r"langchain_google_vertexai",
    r"langchain_google_genai",
    r"google\.adk\b",
    r"ag_sdk\b",
    r"\bgemini-(?:1\.[05]|2\.[05]|exp|pro|flash)\b",
    r"\btext-bison\b",
    r"\bchat-bison\b",
    r"\bcode-bison\b",
    r"\btextembedding-gecko\b",
    r"\bmultimodalembedding\b",
    r"\bimagen-3\.0\b",
    r"Agent Platform Studio\b",
    r"Prompt Gallery\b",
    r"Freeform prompt\b",
    r"Chat prompt\b",
    r"Agent Builder\b",
    r"Model Garden\b",
    r"Gemini in BigQuery\b",
    r"Gemini in Cloud Assist\b",
]

MANUAL_SA_KEY_PATTERNS = [
    r"gcloud\s+iam\s+service-accounts\s+keys\s+create",
    r"iam\.googleapis\.com/serviceAccountKeys\.create",
    r"serviceAccountKeys\.create",
    r"Create\s+service\s+account\s+key",
]

LLM_REGEX = re.compile("|".join(LLM_PATTERNS), re.IGNORECASE)
SA_KEY_REGEX = re.compile("|".join(MANUAL_SA_KEY_PATTERNS), re.IGNORECASE)

# Labs that only enable cloudaicompanion.googleapis.com in TF or use legacy AutoML/Speech/Tabular APIs (not Foundation Models)
NON_FOUNDATION_EXCLUSIONS = {
    "arc130-analyze-sentiment-with-natural-language-api-challenge-lab",
    "arc134-configure-service-accounts-and-iam-for-google-cloud-challenge-lab",
    "sandbox-demo-continuous-sensitive-data-protection-bigquery",
    "sandbox-demo-streaming-data-engineering-esports-use-case",
    "sandbox-demo-heterogeneous-oracle-postgres-alloydb-dms",
    "sandbox-demo-build-and-debug-cloud-funcitons-for-nodejs",
    "sandbox-demo-gke-autopilot-qwik-start",
    "sandbox-demo-agent-platform-tabular-data-qwik-start",
    "sandbox-demo-classify-images-of-clouds-in-the-cloud-with-automl-vision",
    "sandbox-demo-use-cloud-ai-platform-to-train-and-serve-time-series-models",
    "sandbox-demo-identify-damaged-car-parts-agent-platform",
    "sandbox-demo-improving-speech-accuracy",
    "sandbox-demo-measuring-improving-speech-accuracy",
    "test-antigravity-lab",
}


def scan_file_for_patterns(file_path, regex):
    """Scans a file line by line and returns list of (line_num, line_text, match_str)."""
    matches = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                match = regex.search(line)
                if match:
                    matches.append((idx, line.strip(), match.group(0)))
    except Exception as e:
        pass
    return matches


def audit_lab(lab_path):
    """Performs full LLM fleet audit on a lab directory."""
    lab_path = os.path.abspath(lab_path)
    slug = os.path.basename(lab_path)
    sandbox-platform_yaml_path = os.path.join(lab_path, "sandbox.yaml")

    results = {
        "slug": slug,
        "path": lab_path,
        "sandbox-platform_yaml_exists": os.path.exists(sandbox-platform_yaml_path),
        "is_llm_lab": False,
        "llm_matches": [],
        "has_manual_sa_keys": False,
        "sa_key_matches": [],
        "gcp_project_resources": [],
        "all_projects_genai_sandbox": False,
        "compliant": False,
        "status": "UNKNOWN",
        "recommendation": "",
    }

    if not os.path.isdir(lab_path):
        results["status"] = "ERROR_NOT_A_DIRECTORY"
        results["recommendation"] = "Provide a valid lab directory path."
        return results

    # 1. Scan lab directory for LLM signatures and SA Key creation
    for root, _, files in os.walk(lab_path):
        for f in files:
            if f.endswith((".md", ".yaml", ".yml", ".py", ".ipynb", ".tf", ".sh", ".rb")):
                fp = os.path.join(root, f)
                rel_fp = os.path.relpath(fp, lab_path)

                # Skip localized instruction html or vendor folders
                if "instructions/" in rel_fp and rel_fp.endswith(".html"):
                    continue

                # Check LLM matches
                llm_hits = scan_file_for_patterns(fp, LLM_REGEX)
                for line_num, line_text, match_str in llm_hits:
                    results["llm_matches"].append({
                        "file": rel_fp,
                        "line": line_num,
                        "match": match_str,
                        "snippet": line_text[:120],
                    })

                # Check manual SA key creation
                sa_hits = scan_file_for_patterns(fp, SA_KEY_REGEX)
                for line_num, line_text, match_str in sa_hits:
                    results["sa_key_matches"].append({
                        "file": rel_fp,
                        "line": line_num,
                        "match": match_str,
                        "snippet": line_text[:120],
                    })

    results["is_llm_lab"] = len(results["llm_matches"]) > 0 and slug not in NON_FOUNDATION_EXCLUSIONS
    results["has_manual_sa_keys"] = len(results["sa_key_matches"]) > 0
    results["has_managed_ide"] = False
    results["managed_ide_types"] = []

    # 2. Inspect sandbox.yaml
    if results["sandbox-platform_yaml_exists"]:
        # Always check raw YAML text first for Managed Web IDE Proxy resources in case of malformed YAML
        with open(sandbox-platform_yaml_path, "r", encoding="utf-8", errors="ignore") as raw_yf:
            raw_yaml = raw_yf.read()
            raw_bb = re.findall(r"type:\s*(ide|cloud_terminal|looker_instance|jupyter_notebook)\b", raw_yaml)
            if raw_bb:
                results["has_managed_ide"] = True
                results["managed_ide_types"] = list(set(raw_bb))

        try:
            with open(sandbox-platform_yaml_path, "r", encoding="utf-8") as yf:
                config = yaml.safe_load(yf) or {}
                env = config.get("environment", {})
                resources = env.get("resources", [])
                
                project_variants = []
                bb_types = list(results["managed_ide_types"])
                for res in resources:
                    if isinstance(res, dict):
                        rtype = res.get("type")
                        if rtype == "gcp_project":
                            res_id = res.get("id", "unknown_project")
                            variant = res.get("variant", "standard_sandbox (default)")
                            project_variants.append({
                                "id": res_id,
                                "variant": variant,
                            })
                        elif rtype in ("ide", "cloud_terminal", "looker_instance", "jupyter_notebook") and rtype not in bb_types:
                            bb_types.append(rtype)

                results["has_managed_ide"] = len(bb_types) > 0
                results["managed_ide_types"] = bb_types
                results["gcp_project_resources"] = project_variants
                if project_variants:
                    results["all_projects_genai_sandbox"] = all(
                        p.get("variant") == "genai_sandbox" for p in project_variants
                    )
        except Exception as e:
            if results["has_managed_ide"]:
                results["status"] = "managed_ide_proxy_EXCLUDED"
                results["compliant"] = False
                results["recommendation"] = (
                    f"Lab uses Managed Web IDE Proxy ({results['managed_ide_types']}), where ide_provisioner pre-generates "
                    "/home/user/keys.json. Excluded from genai_sandbox per CISO/Fleet policy."
                )
                return results
            results["status"] = f"ERROR_PARSING_YAML: {e}"
            results["recommendation"] = "Fix YAML syntax error in sandbox.yaml."
            return results

    # 3. Determine Compliance and Status
    if results["is_llm_lab"]:
        if results["has_managed_ide"]:
            results["status"] = "managed_ide_proxy_EXCLUDED"
            results["compliant"] = not results["all_projects_genai_sandbox"]
            results["recommendation"] = (
                f"Lab uses Managed Web IDE Proxy ({results['managed_ide_types']}), where ide_provisioner pre-generates "
                "/home/user/keys.json in sandbox-platform-prod GKE (SEC-001). Do NOT migrate to genai_sandbox."
            )
        elif results["has_manual_sa_keys"]:
            results["status"] = "REQUIRES_WORKAROUND_SA_KEY"
            results["compliant"] = False
            results["recommendation"] = (
                "Lab uses LLMs but also creates manual Service Account keys. "
                "Because genai_sandbox denies iam.serviceAccountKeys.create, refactor the lab to use "
                "VM-attached Service Accounts (IMDSv2) or Application Default Credentials (ADC). "
                "NEVER mint a google_service_account_key on an SA with roles/aiplatform.user, roles/editor, or roles/owner (SEC-001)."
            )
        elif results["all_projects_genai_sandbox"]:
            results["status"] = "COMPLIANT"
            results["compliant"] = True
            results["recommendation"] = "Lab is compliant with policy_tier: genai_sandbox."
        else:
            results["status"] = "NEEDS_MIGRATION"
            results["compliant"] = False
            results["recommendation"] = (
                "Lab uses Generative AI / LLMs but is not yet configured with "
                "policy_tier: genai_sandbox in sandbox.yaml. Update gcp_project variant."
            )
    else:
        if results["all_projects_genai_sandbox"]:
            results["status"] = "FLAGGED_NON_LLM_USING_GCP_LLM"
            results["compliant"] = False
            results["recommendation"] = (
                "Lab is configured with policy_tier: genai_sandbox but no LLM usage was detected. "
                "Verify if LLM usage is intended or revert to variant: standard_sandbox."
            )
        else:
            results["status"] = "NON_LLM_LAB"
            results["compliant"] = True
            results["recommendation"] = "Standard lab without LLM usage; no change required."

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Audit a lab directory or repo for LLM usage and genai_sandbox variant compliance."
    )
    parser.add_argument("lab_path", nargs="?", help="Path to individual lab directory.")
    parser.add_argument("--all-labs", help="Path to root repository directory containing all labs (e.g. labs/).")
    parser.add_argument("--json", action="store_true", help="Output results as structured JSON.")
    args = parser.parse_args()

    if args.all_labs:
        all_results = []
        labs_dir = os.path.abspath(args.all_labs)
        for entry in sorted(os.listdir(labs_dir)):
            full_path = os.path.join(labs_dir, entry)
            if os.path.isdir(full_path) and os.path.exists(os.path.join(full_path, "sandbox.yaml")):
                all_results.append(audit_lab(full_path))

        if args.json:
            print(json.dumps(all_results, indent=2))
        else:
            print(f"{'SLUG':<45} | {'IS_LLM':<6} | {'SA_KEY':<6} | {'STATUS':<30}")
            print("-" * 95)
            for r in all_results:
                print(f"{r['slug']:<45} | {str(r['is_llm_lab']):<6} | {str(r['has_manual_sa_keys']):<6} | {r['status']:<30}")
        return

    if not args.lab_path:
        parser.print_help()
        sys.exit(1)

    result = audit_lab(args.lab_path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n=======================================================")
        print(f" LLM Fleet Audit Report: {result['slug']}")
        print("=======================================================")
        print(f" Lab Directory : {result['path']}")
        print(f" Status        : {result['status']}")
        print(f" Compliant     : {'✅ YES' if result['compliant'] else '❌ NO'}")
        print(f" LLM Detected  : {result['is_llm_lab']} ({len(result['llm_matches'])} pattern hits)")
        print(f" Manual SA Key : {result['has_manual_sa_keys']} ({len(result['sa_key_matches'])} pattern hits)")
        print("\n GCP Project Resources:")
        for p in result["gcp_project_resources"]:
            print(f"   - {p['id']}: variant = {p['variant']}")
        print(f"\n Recommendation: {result['recommendation']}")
        print("=======================================================\n")


if __name__ == "__main__":
    main()
