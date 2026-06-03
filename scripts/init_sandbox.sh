#!/usr/bin/env bash
set -euo pipefail

SANDBOX_DIR="${MCP_SANDBOX:-/tmp/mcp_sandbox_secure}"
mkdir -p "$SANDBOX_DIR"
chmod 700 "$SANDBOX_DIR"

# 复制必要文件到沙箱目录（不挂载宿主机源码）
cp -r src/ "$SANDBOX_DIR/"
cp requirements.txt "$SANDBOX_DIR/"

echo "Sandbox ready at $SANDBOX_DIR"
