#!/usr/bin/env bash
# ==============================================================================
# Cloud Sandbox Security Suite — Quick Setup & Multi-Client Installer
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo " 🛡️  Installing GCP Sandbox Security Suite (gcp-sandbox-security)"
echo "======================================================================"

# 1. Verify Python 3
if ! command -v python3 &>/dev/null; then
  echo "❌ Error: python3 is required but not found."
  exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "✅ Found $PYTHON_VERSION"

# 2. Install dependencies (PyYAML is the only requirement)
echo ""
echo "📦 Installing package in editable mode (or installing PyYAML)..."
if command -v pip3 &>/dev/null; then
  pip3 install -e . --quiet || pip3 install pyyaml --quiet
elif command -v pip &>/dev/null; then
  pip install -e . --quiet || pip install pyyaml --quiet
else
  echo "⚠️  pip not found, checking if pyyaml is already available..."
  python3 -c "import yaml" 2>/dev/null || {
    echo "❌ Error: PyYAML is not installed. Please run: pip install pyyaml"
    exit 1
  }
fi
echo "✅ Dependencies verified."

# 3. Detect and configure AI Agent Clients
echo ""
echo "🤖 Checking for AI Agent Clients..."

# Claude Code
if command -v claude &>/dev/null; then
  echo "  Found Claude Code CLI!"
  echo "  To register the MCP server with Claude Code, run:"
  echo "    claude mcp add gcp_sandbox_security -- python3 \"$SCRIPT_DIR/mcp/server.py\" serve"
fi

# Gemini CLI
if [ -d "$HOME/.gemini/config/plugins" ]; then
  echo "  Found Gemini CLI config directory (~/.gemini/config/plugins)!"
  echo "  To register as a plugin (optional):"
  echo "    ln -sfn \"$SCRIPT_DIR\" ~/.gemini/config/plugins/gcp-sandbox-security"
fi

# Cursor
if [ -f "$SCRIPT_DIR/.cursor/mcp.json" ]; then
  echo "  ✅ Cursor MCP configuration ready at .cursor/mcp.json"
fi

# 4. Run Self-Verification Test Suite
echo ""
echo "🧪 Running self-verification integration test suite..."
python3 "$SCRIPT_DIR/mcp/server.py" test

echo ""
echo "======================================================================"
echo " 🎉 Installation & Verification Complete!"
echo "======================================================================"
echo "Try running these instant CLI demos (no LLM required):"
echo "  python3 mcp/server.py audit examples/sandboxes/overprivileged-vertex-agent"
echo "  python3 mcp/server.py validate examples/sandboxes/hardened-cloud-run-reference"
echo "  python3 mcp/server.py recommend examples/sandboxes/overprivileged-vertex-agent"
echo ""
echo "Or start the JSON-RPC stdio server for an AI Agent:"
echo "  python3 mcp/server.py serve"
echo "======================================================================"
