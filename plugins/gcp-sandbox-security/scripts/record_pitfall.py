#!/usr/bin/env python3
"""CLI helper to record security pitfalls into kb/pitfalls.yaml.

Can be run directly from terminal or Cloud Shell by lab testers, authors, or architects.
"""

import argparse
import os
import sys

# Ensure mcp directory is in Python path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.dirname(SCRIPT_DIR)
MCP_DIR = os.path.join(PLUGIN_DIR, "mcp")
sys.path.insert(0, MCP_DIR)

from security_engine import SecurityEngine


def main():
    parser = argparse.ArgumentParser(
        description="Record a newly discovered pitfall or assessment quirk into cloud-sandbox-security knowledge base."
    )
    parser.add_argument("--lab", "-l", required=True, help="Lab slug (e.g. sandbox-demo)")
    parser.add_argument("--symptom", "-s", required=True, help="Observed symptom or error message")
    parser.add_argument("--cause", "-c", required=True, help="Root cause of the failure")
    parser.add_argument("--fix", "-f", required=True, help="Remediation or fix instructions")
    parser.add_argument("--role", "-r", help="Specific required IAM role (e.g. roles/compute.instanceAdmin.v1)")
    parser.add_argument("--resource-type", help="GCP or Terraform resource type (e.g. google_compute_instance)")
    parser.add_argument("--service", help="GCP service name (e.g. compute)")
    parser.add_argument("--id", help="Optional pitfall identifier slug")
    parser.add_argument("--author", "-a", help="Tester or author LDAP/name")
    parser.add_argument(
        "--repo-root",
        default=os.environ.get("LAB_REPO_ROOT", os.path.expanduser("~/repos/cloud-sandboxes")),
        help="Path to target lab content repository",
    )

    args = parser.parse_args()

    engine = SecurityEngine(plugin_dir=PLUGIN_DIR, lab_repo_root=args.repo_root)
    result = engine.record_pitfall(
        lab_slug=args.lab,
        symptom=args.symptom,
        cause=args.cause,
        fix=args.fix,
        pitfall_id=args.id,
        required_role=args.role,
        resource_type=args.resource_type,
        service=args.service,
        author=args.author,
    )

    if result.get("status") == "RECORDED":
        print(f" Successfully recorded pitfall '{result['pitfall_id']}'!")
        print(f"  KB File: {result['kb_file']}")
        print(f"  Total Pitfalls: {result['total_pitfalls']}")
        print("\nNext Steps:")
        for step in result.get("next_steps", []):
            print(f"  - {step}")
    elif result.get("status") == "EXISTS":
        print(f"ℹ️ Pitfall already exists: {result.get('message')}")
    else:
        print(f"❌ Error: {result.get('message')}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
