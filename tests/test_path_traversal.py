"""
Path traversal attack tests against the secure MCP server (port 8766).
Payloads are loaded from exploits/payloads.json.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time

import pytest

from mcp import ClientSession, types
from mcp.client.sse import sse_client

# ---------------------------------------------------------------------------
# Constants & payload loading (module-level for parametrize)
# ---------------------------------------------------------------------------

SECURE_URL = "http://127.0.0.1:8766/sse"

_PAYLOADS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "exploits", "payloads.json"
)
with open(_PAYLOADS_PATH) as _f:
    _ALL = json.load(_f)

TRAVERSAL = [(p["name"], p["payload"]["path"]) for p in _ALL if p.get("category") == "path_traversal"]
POISONING = [(p["name"], p["payload"]["path"], p["payload"].get("reason", ""))
             for p in _ALL if p.get("category") == "argument_poisoning"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text(result: types.CallToolResult) -> str:
    first = result.content[0]
    if isinstance(first, types.TextContent):
        return first.text
    return str(first)


async def _call(url: str, tool: str, args: dict) -> types.CallToolResult:
    async with sse_client(url) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            return await session.call_tool(tool, args)


# ---------------------------------------------------------------------------
# Server fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def secure_server():
    proc = subprocess.Popen(
        ["python3", "src/probe_server_secure.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    yield
    proc.terminate()
    proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Secure server — traversal payloads ARE blocked
# ---------------------------------------------------------------------------

class TestSecureTraversal:
    """Secure server blocks all traversal attempts with ToolError."""

    @pytest.fixture(autouse=True, scope="class")
    def _start(self, secure_server):
        pass

    @pytest.mark.parametrize("name,path", TRAVERSAL)
    def test_traversal_blocked(self, name, path):
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": path}))
        text = _text(result)
        assert result.isError, f"{name}: expected isError=True, got: {text[:100]}"
        # Encoded payloads may pass sandbox validation but still fail to read
        # (no leak). Only assert security/traversal keywords for non-encoded paths.
        if "%" not in path:
            assert "Security" in text or "traversal" in text.lower(), (
                f"{name}: expected security/traversal error, got: {text[:100]}"
            )

    @pytest.mark.parametrize("name,path,reason", POISONING)
    def test_argument_poisoning_blocked(self, name, path, reason):
        args = {"path": path}
        if reason:
            args["reason"] = reason
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", args))
        assert result.isError, f"{name}: expected isError=True"

    def test_legitimate_hello_txt(self):
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "hello.txt"}))
        text = _text(result)
        assert "[OK]" in text
        assert "Hello" in text

    def test_subdir_parent_resolve(self):
        """subdir/../hello.txt resolves correctly within the sandbox."""
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "subdir/../hello.txt"}))
        text = _text(result)
        assert "[OK]" in text
        assert "Hello" in text


# ---------------------------------------------------------------------------
# Edge cases — secure server only
# ---------------------------------------------------------------------------

class TestSecureEdgeCases:
    """Additional edge-case path validation on the secure server."""

    @pytest.fixture(autouse=True, scope="class")
    def _start(self, secure_server):
        pass

    def test_absolute_path_blocked(self):
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "/etc/passwd"}))
        assert result.isError

    def test_mixed_traversal_blocked(self):
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "subdir/../../etc/passwd"}))
        assert result.isError

    def test_empty_path_blocked(self):
        result = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": ""}))
        assert result.isError

    def test_legitimate_write(self):
        """Write to sandbox should succeed on secure server."""
        result = asyncio.run(_call(SECURE_URL, "write_file",
                                    {"path": "test_write.txt", "content": "hello"}))
        text = _text(result)
        assert "[OK]" in text

    def test_write_traversal_blocked(self):
        """Write outside sandbox should be blocked."""
        result = asyncio.run(_call(SECURE_URL, "write_file",
                                    {"path": "../../../tmp/pwned.txt", "content": "x"}))
        assert result.isError
