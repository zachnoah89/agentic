#!/usr/bin/env python3
"""generate_genai_inventory.py: Generates Master Inventory CSV for LLM labs and variant status.

Usage:
    python3 generate_genai_inventory.py --labs-dir /path/to/cloud-sandboxes/labs --output-csv assets/sample_fleet_inventory.csv
"""

import argparse
import csv
import os
import sys
import yaml

# Import audit logic from audit_llm_lab
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_llm_lab import audit_lab


def generate_inventory(labs_dir, output_csv, repo_name="cloud-sandboxes"):
    """Scans all labs in labs_dir and writes structured master inventory CSV."""
    labs_dir = os.path.abspath(labs_dir)
    os.makedirs(os.path.dirname(os.path.abspath(output_csv)), exist_ok=True)

    print(f"Scanning labs in: {labs_dir}...")
    inventory = []
    
    entries = sorted(os.listdir(labs_dir))
    total_entries = len(entries)
    
    for idx, entry in enumerate(entries, start=1):
        lab_path = os.path.join(labs_dir, entry)
        if not os.path.isdir(lab_path) or not os.path.exists(os.path.join(lab_path, "sandbox.yaml")):
            continue

        audit_res = audit_lab(lab_path)
        
        current_variants = [p.get("variant", "standard_sandbox") for p in audit_res["gcp_project_resources"]]
        curr_variant_str = ",".join(current_variants) if current_variants else "standard_sandbox (implicit)"

        is_llm = audit_res["is_llm_lab"]
        has_sa_keys = audit_res["has_manual_sa_keys"]

        if is_llm and has_sa_keys:
            status = "MANUAL_SA_KEY_CREATION_REQUIRES_WORKAROUND"
            target_variant = "genai_sandbox (blocked on SA key fix)"
        elif is_llm and audit_res["all_projects_genai_sandbox"]:
            status = "COMPLIANT"
            target_variant = "genai_sandbox"
        elif is_llm:
            status = "NEEDS_MIGRATION"
            target_variant = "genai_sandbox"
        else:
            status = "NON_LLM_LAB"
            target_variant = curr_variant_str

        # Distinct pattern matches
        distinct_matches = list({m["match"] for m in audit_res["llm_matches"]})[:4]
        matches_summary = "; ".join(distinct_matches)

        inventory.append({
            "slug": audit_res["slug"],
            "repo": repo_name,
            "is_llm_lab": "YES" if is_llm else "NO",
            "current_variant": curr_variant_str,
            "target_variant": target_variant,
            "has_manual_sa_keys": "YES" if has_sa_keys else "NO",
            "status": status,
            "detection_hits": len(audit_res["llm_matches"]),
            "key_patterns": matches_summary,
            "recommendation": audit_res["recommendation"],
        })

    # Write CSV
    fieldnames = [
        "slug",
        "repo",
        "is_llm_lab",
        "current_variant",
        "target_variant",
        "has_manual_sa_keys",
        "status",
        "detection_hits",
        "key_patterns",
        "recommendation",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in inventory:
            writer.writerow(row)

    print(f"✅ Successfully wrote {len(inventory)} rows to {output_csv}")

    # Print summary statistics
    llm_count = sum(1 for r in inventory if r["is_llm_lab"] == "YES")
    needs_mig = sum(1 for r in inventory if r["status"] == "NEEDS_MIGRATION")
    sa_workaround = sum(1 for r in inventory if r["status"] == "MANUAL_SA_KEY_CREATION_REQUIRES_WORKAROUND")
    compliant = sum(1 for r in inventory if r["status"] == "COMPLIANT")
    non_llm = sum(1 for r in inventory if r["status"] == "NON_LLM_LAB")

    print("\n--- Summary Statistics ---")
    print(f"Total Labs Audited       : {len(inventory)}")
    print(f"LLM Labs Identified      : {llm_count}")
    print(f" - Needs Migration (Clean): {needs_mig}")
    print(f" - Needs SA Key Workaround: {sa_workaround}")
    print(f" - Already Compliant     : {compliant}")
    print(f"Non-LLM Labs (No Action) : {non_llm}")
    print("--------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="Generate Master Inventory CSV for LLM labs.")
    parser.add_argument(
        "--labs-dir",
        default=os.path.expanduser("~/repos/cloud-sandboxes/labs"),
        help="Path to labs directory.",
    )
    parser.add_argument(
        "--output-csv",
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "assets",
            "sample_fleet_inventory.csv",
        ),
        help="Path for output CSV file.",
    )
    parser.add_argument("--repo-name", default="cloud-sandboxes", help="Repository identifier name.")
    args = parser.parse_args()

    generate_inventory(args.labs_dir, args.output_csv, args.repo_name)


if __name__ == "__main__":
    main()
