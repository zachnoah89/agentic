#!/usr/bin/env python3
"""Zero-dependency MCP stdio server for cloud-sandbox-security.

Implements JSON-RPC 2.0 over stdin/stdout.
STRICT INVARIANT: stdout must ONLY contain valid single-line JSON-RPC messages.
All diagnostic logging, traces, and debug info must go to stderr.
"""

import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

# Configure logging strictly to stderr
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[cloud-sandbox-security %(asctime)s] [%(levelname)s] %(message)s",
)
logger = logging.getLogger("cloud-sandbox-security-mcp")

# Supported MCP protocol versions
KNOWN_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
FALLBACK_PROTOCOL = "2024-11-05"

# Base directory paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

PLUGIN_DIR = os.environ.get(
    "PLUGIN_DIR", os.path.dirname(SCRIPT_DIR)
)
KB_DIR = os.path.join(PLUGIN_DIR, "kb")
LAB_REPO_ROOT = os.environ.get(
    "SANDBOX_REPO_ROOT",
    os.environ.get("LAB_REPO_ROOT", os.path.join(PLUGIN_DIR, "examples")),
)

# Initialize Security Engine
try:
    from security_engine import SecurityEngine
except ImportError:
    from .security_engine import SecurityEngine

engine = SecurityEngine(plugin_dir=PLUGIN_DIR, lab_repo_root=LAB_REPO_ROOT)

# Registry of tools: tool_name -> {"spec": dict, "handler": callable}
TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_tool(spec: Dict[str, Any]):
    """Decorator to register a tool definition and handler."""

    def decorator(func: Callable[[Dict[str, Any]], Dict[str, Any]]):
        TOOL_REGISTRY[spec["name"]] = {
            "spec": spec,
            "handler": func,
        }
        return func

    return decorator


def format_tool_response(data: Any, is_error: bool = False) -> Dict[str, Any]:
    """Formats output as standard MCP tool content."""
    text_content = json.dumps(data, indent=2) if not isinstance(data, str) else data
    resp = {"content": [{"type": "text", "text": text_content}]}
    if is_error:
        resp["isError"] = True
    return resp


# ---------------------------------------------------------------------------
# Tool Declarations & Handlers
# ---------------------------------------------------------------------------


@register_tool(
    {
        "name": "ping",
        "description": "Health check verifying JSON-RPC 2.0 stdio connectivity, server metadata, and environment paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Optional echo message",
                }
            },
        },
    }
)
def handle_ping(args: Dict[str, Any]) -> Dict[str, Any]:
    echo = args.get("message", "pong")
    return format_tool_response({
        "status": "ok",
        "echo": echo,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server": "cloud-sandbox-security",
        "version": "0.1.0-beta",
        "plugin_dir": PLUGIN_DIR,
        "kb_dir": KB_DIR,
        "kb_exists": os.path.isdir(KB_DIR),
        "lab_repo_root": LAB_REPO_ROOT,
        "lab_repo_exists": os.path.isdir(LAB_REPO_ROOT),
    })


@register_tool(
    {
        "name": "recommend_iam_roles",
        "description": "Primary entry point. Analyzes lab configurations, classifies archetypes, and returns minimal scoped IAM roles, roles to remove, and applicable pitfalls.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path (e.g. 'arc100-store-process-and-manage-data-challenge-lab').",
                }
            },
            "required": ["lab_slug"],
        },
    }
)
def handle_recommend_iam_roles(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    res = engine.recommend_iam_roles(slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "lookup_roles",
        "description": "Provides role recommendations and risk profiles for greenfield lab design without requiring an existing lab directory on disk.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "archetype": {
                    "type": "string",
                    "description": "Archetype name or ID (e.g. 'vertex-ai-workbench', 'bigtable-developer').",
                },
                "services": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of GCP service names (e.g. ['compute', 'storage', 'bigquery']).",
                },
            },
        },
    }
)
def handle_lookup_roles(args: Dict[str, Any]) -> Dict[str, Any]:
    arch = args.get("archetype")
    services = args.get("services")
    res = engine.lookup_roles(archetype=arch, services=services)
    return format_tool_response(res)


@register_tool(
    {
        "name": "explain_pitfall",
        "description": "Retrieves detailed symptom, cause, and remediation guidance for known security pitfalls or lab failure modes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "topic": {
                    "type": "string",
                    "description": "Keyword or pitfall ID (e.g. 'bigtable', 'mustache', 'sudo', 'ssh').",
                },
                "lab_slug": {
                    "type": "string",
                    "description": "Optional lab slug to retrieve pitfalls specific to that lab's archetype.",
                },
            },
        },
    }
)
def handle_explain_pitfall(args: Dict[str, Any]) -> Dict[str, Any]:
    topic = args.get("topic")
    slug = args.get("lab_slug")
    res = engine.explain_pitfall(topic=topic, lab_slug=slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "record_pitfall",
        "description": "Records a newly discovered security pitfall, IAM constraint, or assessment grading quirk into kb/pitfalls.yaml for collective team learning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path where the issue was observed (e.g. 'sandbox-demo').",
                },
                "symptom": {
                    "type": "string",
                    "description": "Observed symptom or error message (e.g. 'Ruby assessment check task 3 fails with 403 Forbidden on Compute metadata').",
                },
                "cause": {
                    "type": "string",
                    "description": "Root cause of the failure (e.g. 'Assessment script probes VM by injecting SSH metadata, requiring instance admin').",
                },
                "fix": {
                    "type": "string",
                    "description": "Remediation action (e.g. 'Grant roles/compute.instanceAdmin.v1 to user_0 in sandbox.yaml').",
                },
                "pitfall_id": {
                    "type": "string",
                    "description": "Optional unique slug identifier (e.g. 'sandbox-demo-compute-metadata-ssh'). Generated automatically if omitted.",
                },
                "required_role": {
                    "type": "string",
                    "description": "Optional specific IAM role required (e.g. 'roles/compute.instanceAdmin.v1').",
                },
                "resource_type": {
                    "type": "string",
                    "description": "Optional GCP or Terraform resource type (e.g. 'google_compute_instance').",
                },
                "service": {
                    "type": "string",
                    "description": "Optional GCP service name (e.g. 'compute').",
                },
                "author": {
                    "type": "string",
                    "description": "Optional author/tester identifier (e.g. 'znoah' or tester LDAP).",
                },
            },
            "required": ["lab_slug", "symptom", "cause", "fix"],
        },
    }
)
def handle_record_pitfall(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    symptom = args.get("symptom")
    cause = args.get("cause")
    fix = args.get("fix")
    pitfall_id = args.get("pitfall_id")
    required_role = args.get("required_role")
    resource_type = args.get("resource_type")
    service = args.get("service")
    author = args.get("author")
    res = engine.record_pitfall(
        lab_slug=slug,
        symptom=symptom,
        cause=cause,
        fix=fix,
        pitfall_id=pitfall_id,
        required_role=required_role,
        resource_type=resource_type,
        service=service,
        author=author,
    )
    return format_tool_response(res)


@register_tool(
    {
        "name": "classify_lab",
        "description": "Classifies a lab directory against archetype definitions and returns matched patterns.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path.",
                }
            },
            "required": ["lab_slug"],
        },
    }
)
def handle_classify_lab(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    res = engine.classify_lab(slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "audit_lab",
        "description": "Performs a deterministic security and syntax audit on sandbox.yaml, Terraform, assessments, and instructions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path.",
                }
            },
            "required": ["lab_slug"],
        },
    }
)
def handle_audit_lab(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    res = engine.audit_lab(slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "validate_pre_merge",
        "description": "Enforces mandatory pre-merge gate (PASS/FAIL). Verifies no dev admin, no owner/editor, egress rules present, and valid instruction syntax.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path.",
                }
            },
            "required": ["lab_slug"],
        },
    }
)
def handle_validate_pre_merge(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    res = engine.validate_pre_merge(slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "get_fleet_status",
        "description": "Dynamically scans the lab repository catalog to calculate fleet-wide hardening status without relying on static CSV files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Optional path to lab repository (defaults to $LAB_REPO_ROOT/labs).",
                },
                "filter_status": {
                    "type": "string",
                    "enum": ["hardened", "partial", "untouched"],
                    "description": "Filter by hardening status.",
                },
            },
        },
    }
)
def handle_get_fleet_status(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path")
    status_filter = args.get("filter_status")
    res = engine.get_fleet_status(repo_path=repo_path, filter_status=status_filter)
    return format_tool_response(res)


@register_tool(
    {
        "name": "get_backlog",
        "description": "Dynamically identifies and scores high-risk unhardened labs across the catalog, ranked by vulnerability severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {
                    "type": "string",
                    "description": "Optional path to lab repository.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of prioritized labs to return (default 10).",
                },
            },
        },
    }
)
def handle_get_backlog(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path")
    limit = args.get("limit", 10)
    res = engine.get_backlog(repo_path=repo_path, limit=limit)
    return format_tool_response(res)


@register_tool(
    {
        "name": "apply_security_patch",
        "description": "Inspects and updates lab files in place or returns dry-run diffs to remediate security findings while preserving lab objectives.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Target lab slug or path.",
                },
                "patch_type": {
                    "type": "string",
                    "enum": [
                        "egress_firewall",
                        "disable_imds_v1",
                        "minimize_iam_roles",
                        "fix_mustache",
                        "runtime_yaml",
                    ],
                    "description": "Type of remediation patch to apply.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, generates preview diff without modifying files (default true).",
                },
            },
            "required": ["lab_slug", "patch_type"],
        },
    }
)
def handle_apply_security_patch(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    patch_type = args.get("patch_type")
    dry_run = args.get("dry_run", True)
    res = engine.apply_security_patch(slug, patch_type=patch_type, dry_run=dry_run)
    return format_tool_response(res)


@register_tool(
    {
        "name": "check_exception",
        "description": "Checks whether a lab has an approved security or hardening exception recorded in kb/exceptions.yaml.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path (e.g. 'sandbox-demo-security-challenge-lab').",
                }
            },
            "required": ["lab_slug"],
        },
    }
)
def handle_check_exception(args: Dict[str, Any]) -> Dict[str, Any]:
    slug = args.get("lab_slug")
    res = engine.check_exception(slug)
    return format_tool_response(res)


@register_tool(
    {
        "name": "record_pitfall",
        "description": "Records a newly discovered security pitfall, IAM constraint, or assessment grading quirk into kb/pitfalls.yaml for collective team learning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lab_slug": {
                    "type": "string",
                    "description": "Lab slug or directory path where the issue was observed (e.g. 'sandbox-demo').",
                },
                "symptom": {
                    "type": "string",
                    "description": "Observed symptom or error message.",
                },
                "cause": {
                    "type": "string",
                    "description": "Root cause of the failure or security exposure.",
                },
                "fix": {
                    "type": "string",
                    "description": "Remediation action or fix instructions.",
                },
                "pitfall_id": {
                    "type": "string",
                    "description": "Optional unique slug identifier. Generated automatically if omitted.",
                },
                "required_role": {
                    "type": "string",
                    "description": "Optional specific IAM role required.",
                },
                "resource_type": {
                    "type": "string",
                    "description": "Optional GCP or Terraform resource type.",
                },
                "service": {
                    "type": "string",
                    "description": "Optional GCP service name.",
                },
                "author": {
                    "type": "string",
                    "description": "Optional author/tester identifier.",
                },
            },
            "required": ["lab_slug", "symptom", "cause", "fix"],
        },
    }
)
def handle_record_pitfall(args: Dict[str, Any]) -> Dict[str, Any]:
    res = engine.record_pitfall(
        lab_slug=args.get("lab_slug"),
        symptom=args.get("symptom"),
        cause=args.get("cause"),
        fix=args.get("fix"),
        pitfall_id=args.get("pitfall_id"),
        required_role=args.get("required_role"),
        resource_type=args.get("resource_type"),
        service=args.get("service"),
        author=args.get("author"),
    )
    return format_tool_response(res)


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher
# ---------------------------------------------------------------------------


def make_response(
    req_id: Optional[Any], result: Optional[Any] = None, error: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Constructs a standard JSON-RPC 2.0 response."""
    if req_id is None:
        return None  # Notifications MUST NOT elicit a response
    resp: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        resp["error"] = error
    else:
        resp["result"] = result if result is not None else {}
    return resp


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Processes a single parsed JSON-RPC request dictionary."""
    if not isinstance(req, dict):
        return make_response(
            None, error={"code": -32600, "message": "Invalid Request: expected JSON object"}
        )

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {}) or {}

    logger.debug(f"Handling method={method}, id={req_id}")

    if method == "initialize":
        client_proto = params.get("protocolVersion")
        negotiated_proto = (
            client_proto if client_proto in KNOWN_PROTOCOLS else FALLBACK_PROTOCOL
        )
        return make_response(
            req_id,
            {
                "protocolVersion": negotiated_proto,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "cloud-sandbox-security",
                    "version": "0.1.0-beta",
                },
            },
        )

    if method == "notifications/initialized":
        logger.info("Client acknowledged initialization.")
        return None

    if method == "ping":
        return make_response(req_id, {})

    if method == "tools/list":
        tools_list = [entry["spec"] for entry in TOOL_REGISTRY.values()]
        return make_response(req_id, {"tools": tools_list})

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {}) or {}

        if tool_name not in TOOL_REGISTRY:
            return make_response(
                req_id,
                error={
                    "code": -32601,
                    "message": f"Tool '{tool_name}' not found",
                },
            )

        handler = TOOL_REGISTRY[tool_name]["handler"]
        try:
            result = handler(tool_args)
            return make_response(req_id, result)
        except Exception as e:
            logger.error(f"Error executing tool '{tool_name}': {e}\n{traceback.format_exc()}")
            return make_response(
                req_id,
                {
                    "content": [{"type": "text", "text": f"Error executing tool '{tool_name}': {str(e)}"}],
                    "isError": True,
                },
            )

    # Unknown method
    if req_id is not None:
        return make_response(
            req_id,
            error={
                "code": -32601,
                "message": f"Method '{method}' not found",
            },
        )
    return None


def run_server():
    """Main event loop: reads JSON-RPC requests from stdin, outputs to stdout."""
    logger.info("Starting cloud-sandbox-security MCP server...")
    logger.info(f"PLUGIN_DIR: {PLUGIN_DIR}")
    logger.info(f"KB_DIR: {KB_DIR}")
    logger.info(f"LAB_REPO_ROOT: {LAB_REPO_ROOT}")
    logger.info(f"Registered {len(TOOL_REGISTRY)} tools: {list(TOOL_REGISTRY.keys())}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as err:
            logger.error(f"Failed to parse JSON input line: {err}")
            sys.stdout.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {err}"},
                    }
                )
                + "\n"
            )
            sys.stdout.flush()
            continue

        resp = handle_request(req)
        if resp is not None:
            serialized = json.dumps(resp)
            sys.stdout.write(serialized + "\n")
            sys.stdout.flush()


def _print_audit_report(res: Dict[str, Any]):
    """Pretty prints deterministic audit results to terminal."""
    slug = res.get("lab_slug", "Unknown")
    findings = res.get("findings", [])
    crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    warn = sum(1 for f in findings if f.get("severity") == "WARNING")
    info = sum(1 for f in findings if f.get("severity") == "INFO")
    total = len(findings)

    print("\n" + "=" * 70)
    print(f" 🛡️  CLOUD SANDBOX SECURITY AUDIT: {slug}")
    print("=" * 70)
    print(f" Summary: {total} Findings (CRITICAL: {crit} | HIGH: {high} | WARNING: {warn} | INFO: {info})\n")

    if total == 0:
        print("  ✅ All deterministic checks PASSED! Zero security violations detected.\n")
        return

    for idx, f in enumerate(res.get("findings", []), 1):
        sev = f.get("severity", "INFO")
        badge = f"[{sev}]"
        print(f" {idx}. {badge:10} {f.get('rule_id')} ({f.get('file')})")
        print(f"    Message:     {f.get('message')}")
        if f.get("remediation"):
            print(f"    Remediation: {f.get('remediation')}")
        print()


def _print_validate_report(res: Dict[str, Any]):
    """Pretty prints pre-merge validation gate report."""
    status = res.get("status", "UNKNOWN")
    slug = res.get("lab_slug", "Unknown")
    blocks = res.get("blocking_violations_count", 0)

    print("\n" + "=" * 70)
    print(f" 🚦 PRE-MERGE SECURITY GATE: {slug}")
    print("=" * 70)
    if status in ("PASS", "PASS_WITH_EXCEPTION"):
        print(f" Status: ✅ {status}")
    else:
        print(f" Status: ❌ {status} ({blocks} Blocking Violations)")

    print(f" Message: {res.get('message')}")
    if res.get("blocking_violations"):
        print("\n Blocking Findings:")
        for idx, bv in enumerate(res.get("blocking_violations"), 1):
            print(f"  {idx}. [{bv.get('severity')}] {bv.get('rule_id')} in {bv.get('file')}")
            print(f"     {bv.get('message')}")
    print()


def _print_recommend_report(res: Dict[str, Any]):
    """Pretty prints IAM role recommendations and pitfalls."""
    slug = res.get("lab_slug", "Unknown")
    print("\n" + "=" * 70)
    print(f" 🔑 LEAST-PRIVILEGE IAM RECOMMENDATIONS: {slug}")
    print("=" * 70)
    print(" Recommended Minimal Roles:")
    for r in res.get("recommended_roles", []):
        print(f"  + {r.get('role'):40} (Reason: {r.get('reason')})")

    if res.get("roles_to_remove"):
        print("\n Roles to Remove (Over-privileged):")
        for rr in res.get("roles_to_remove", []):
            print(f"  - {rr}")

    if res.get("applicable_pitfalls"):
        print("\n Operational Pitfalls & Grading Traps:")
        for idx, p in enumerate(res.get("applicable_pitfalls", []), 1):
            print(f"  {idx}. [{p.get('id')}] {p.get('symptom')}")
            print(f"     Cause: {p.get('cause')}")
            print(f"     Fix:   {p.get('fix')}")
    print()


def main():
    """Dual-mode entry point: CLI commands or MCP JSON-RPC server."""
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "serve":
            run_server()
            return 0
        if cmd == "audit" and len(sys.argv) > 2:
            target = sys.argv[2]
            res = engine.audit_lab(target)
            if "--json" in sys.argv:
                print(json.dumps(res, indent=2))
            else:
                _print_audit_report(res)
            return 1 if res.get("critical_count", 0) > 0 or res.get("high_count", 0) > 0 else 0
        if cmd == "validate" and len(sys.argv) > 2:
            target = sys.argv[2]
            res = engine.validate_pre_merge(target)
            if "--json" in sys.argv:
                print(json.dumps(res, indent=2))
            else:
                _print_validate_report(res)
            return 0 if res.get("status") in ("PASS", "PASS_WITH_EXCEPTION") else 1
        if cmd == "recommend" and len(sys.argv) > 2:
            target = sys.argv[2]
            res = engine.recommend_iam_roles(target)
            if "--json" in sys.argv:
                print(json.dumps(res, indent=2))
            else:
                _print_recommend_report(res)
            return 0
        if cmd == "fleet":
            res = engine.get_fleet_status()
            print(json.dumps(res, indent=2))
            return 0
        if cmd == "test":
            import unittest
            suite = unittest.defaultTestLoader.discover(SCRIPT_DIR, pattern="test_*.py")
            runner = unittest.TextTestRunner(verbosity=2)
            result = runner.run(suite)
            return 0 if result.wasSuccessful() else 1
        if cmd in ("-h", "--help", "help"):
            print("Usage: cloud-sandbox-security <command> [options]\n")
            print("Commands:")
            print("  audit <slug_or_path>      Run deterministic static security audit")
            print("  validate <slug_or_path>   Run pre-merge validation gate (PASS/FAIL)")
            print("  recommend <slug_or_path>  Compute least-privilege IAM roles and pitfalls")
            print("  fleet                     Show catalog hardening metrics")
            print("  test                      Run internal test suite")
            print("  serve                     Start JSON-RPC 2.0 MCP server over stdio")
            return 0

    # If piped/redirected (standard MCP runner invocation like Claude Code / Cursor)
    if not sys.stdin.isatty():
        run_server()
        return 0

    # If run in an interactive terminal with no args, print friendly banner
    print("======================================================================")
    print(" 🛡️  Cloud Sandbox Security Suite (Dual-Mode MCP Server & Security CLI)")
    print("======================================================================")
    print("Usage: cloud-sandbox-security <command> [args]\n")
    print("Instant Demos:")
    print("  cloud-sandbox-security audit examples/sandboxes/overprivileged-vertex-agent")
    print("  cloud-sandbox-security validate examples/sandboxes/hardened-cloud-run-reference")
    print("  cloud-sandbox-security recommend examples/sandboxes/overprivileged-vertex-agent")
    print("  cloud-sandbox-security test")
    print("  cloud-sandbox-security serve    # Starts JSON-RPC 2.0 stdio server for AI agents\n")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
