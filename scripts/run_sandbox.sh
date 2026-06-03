#!/usr/bin/env bash
set -euo pipefail

NETWORK_MODE="${MCP_NETWORK_MODE:-none}"
SANDBOX_DIR="${MCP_SANDBOX:-/tmp/mcp_sandbox_secure}"
API_KEY="${MCP_API_KEY:-dev-key-change-in-prod}"

# 使用 unshare 创建轻量隔离（PID + 网络命名空间）
if [ "$NETWORK_MODE" = "none" ]; then
    unshare --net --pid --fork --mount-proc \
        python "$SANDBOX_DIR/src/probe_server_secure.py" \
        --sandbox-dir "$SANDBOX_DIR" \
        --api-key "$API_KEY"
else
    python "$SANDBOX_DIR/src/probe_server_secure.py" \
        --sandbox-dir "$SANDBOX_DIR" \
        --api-key "$API_KEY"
fi
