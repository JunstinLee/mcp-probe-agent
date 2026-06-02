"""
A-B comparison tests: run identical requests against both vulnerable (8765)
and secure (8766) servers, then verify the expected behavioural differences.
"""

from __future__ import annotations

import asyncio
import subprocess
import time

import pytest

from mcp import ClientSession, types
from mcp.client.sse import sse_client

VULN_URL = "http://127.0.0.1:8765/sse"
SECURE_URL = "http://127.0.0.1:8766/sse"


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
def vuln_server():
    proc = subprocess.Popen(
        ["python3", "src/probe_server.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    yield
    proc.terminate()
    proc.wait(timeout=5)


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
# A-B Comparison Tests
# ---------------------------------------------------------------------------

class TestABComparison:
    """Each test sends the same request to both servers and verifies the
    expected behavioural difference."""

    @pytest.fixture(autouse=True, scope="class")
    def _servers(self, vuln_server, secure_server):
        pass

    # -- legitimate reads (both succeed) --

    def test_read_hello_txt_both_succeed(self):
        """Both servers should return the seed file content."""
        v = _text(asyncio.run(_call(VULN_URL, "read_secure_file", {"path": "hello.txt"})))
        s = _text(asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "hello.txt"})))
        assert "Hello" in v
        assert "Hello" in s

    def test_query_users_both_succeed(self):
        """Both servers should return user data."""
        v = _text(asyncio.run(_call(VULN_URL, "query_mock_db", {"table": "users"})))
        s = _text(asyncio.run(_call(SECURE_URL, "query_mock_db", {"table": "users"})))
        assert "Alice" in v
        assert "Alice" in s

    # -- traversal: vuln leaks, secure blocks --

    def test_traversal_vuln_leaks_secure_blocks(self):
        v = asyncio.run(_call(VULN_URL, "read_secure_file", {"path": "../../etc/passwd"}))
        s = asyncio.run(_call(SECURE_URL, "read_secure_file", {"path": "../../etc/passwd"}))
        assert not v.isError, "vulnerable server should leak"
        assert s.isError, "secure server should block"

    # -- write inside sandbox: both succeed --

    def test_write_inside_sandbox_both_succeed(self):
        v = _text(asyncio.run(_call(VULN_URL, "write_file", {"path": "ab_test.txt", "content": "ok"})))
        s = _text(asyncio.run(_call(SECURE_URL, "write_file", {"path": "ab_test.txt", "content": "ok"})))
        assert "[OK]" in v
        assert "[OK]" in s

    # -- write outside sandbox: vuln succeeds, secure blocks --

    def test_write_traversal_vuln_succeeds_secure_blocks(self):
        v = asyncio.run(_call(VULN_URL, "write_file",
                               {"path": "../../../tmp/ab_pwned.txt", "content": "x"}))
        s = asyncio.run(_call(SECURE_URL, "write_file",
                               {"path": "../../../tmp/ab_pwned.txt", "content": "x"}))
        assert not v.isError, "vulnerable server should allow write outside sandbox"
        assert s.isError, "secure server should block write outside sandbox"

    # -- scrape: vuln leaks injection, secure sanitizes --

    def test_scrape_vuln_leaks_secure_sanitizes(self):
        v = _text(asyncio.run(_call(VULN_URL, "scrape_webpage", {"url": "http://x.com"})))
        s = _text(asyncio.run(_call(SECURE_URL, "scrape_webpage", {"url": "http://x.com"})))
        assert "Ignore previous instructions" in v
        assert "Ignore previous instructions" not in s
        assert "<tool_output>" in s

    # -- secrets table: vuln reveals, secure blocks --

    def test_secrets_vuln_reveals_secure_blocks(self):
        v = asyncio.run(_call(VULN_URL, "query_mock_db", {"table": "secrets"}))
        s = asyncio.run(_call(SECURE_URL, "query_mock_db", {"table": "secrets"}))
        vt = _text(v)
        assert "hunter2" in vt or "sk-mock" in vt, "vulnerable should leak secrets"
        assert s.isError, "secure should block secrets access"

    # -- non-existent tool: both error --

    def test_nonexistent_tool_both_error(self):
        v = asyncio.run(_call(VULN_URL, "nonexistent_tool", {}))
        s = asyncio.run(_call(SECURE_URL, "nonexistent_tool", {}))
        vt = _text(v)
        assert "Unknown tool" in vt or v.isError
        assert s.isError

    # -- missing required argument: both error --

    def test_missing_arg_both_error(self):
        v = asyncio.run(_call(VULN_URL, "read_secure_file", {}))
        s = asyncio.run(_call(SECURE_URL, "read_secure_file", {}))
        vt = _text(v)
        assert v.isError or "error" in vt.lower() or "[ERR]" in vt
        assert s.isError
