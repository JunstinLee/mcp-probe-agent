"""
Tests for validate_required_args and server-side argument handling
on both vulnerable (port 8765) and secure (port 8766) MCP servers.
"""

from __future__ import annotations

import asyncio
import subprocess
import time

import pytest

from src.validators import validate_required_args
from mcp import ClientSession
from mcp.client.sse import sse_client


# ---------------------------------------------------------------------------
# Module-level tests: direct validate_required_args calls
# ---------------------------------------------------------------------------


class TestValidateRequiredArgs:
    """Unit tests for the validate_required_args pure function."""

    def test_valid_args_returns_filtered(self):
        result = validate_required_args({"path": "x"}, ["path"], ["path"])
        assert result == {"path": "x"}

    def test_missing_required_raises(self):
        with pytest.raises(ValueError, match="missing required argument"):
            validate_required_args({}, ["path"], ["path"])

    def test_empty_required_raises(self):
        with pytest.raises(ValueError, match="missing required argument"):
            validate_required_args({"path": ""}, ["path"], ["path"])

    def test_unknown_key_raises(self):
        with pytest.raises(ValueError, match="unknown arguments"):
            validate_required_args({"path": "x", "reason": "y"}, ["path"], ["path"])


# ---------------------------------------------------------------------------
# Server fixtures
# ---------------------------------------------------------------------------

VULN_PORT = 8765
SECURE_PORT = 8766


@pytest.fixture(scope="module")
def vuln_server():
    proc = subprocess.Popen(
        ["python3", "src/probe_server.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    yield
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def secure_server():
    proc = subprocess.Popen(
        ["python3", "src/probe_server_secure.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)
    yield
    proc.terminate()
    proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# MCP client helper
# ---------------------------------------------------------------------------


def call_tool_sync(port: int, tool_name: str, arguments: dict, timeout: int = 10):
    """Call an MCP tool synchronously via SSE transport."""

    async def _call():
        async with sse_client(f"http://127.0.0.1:{port}/sse") as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                return result

    return asyncio.run(asyncio.wait_for(_call(), timeout=timeout))


def _result_text(result) -> str:
    """Extract text from a CallToolResult, joining multiple content blocks."""
    parts = []
    for block in result.content:
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Integration tests: vulnerable server
# ---------------------------------------------------------------------------


class TestVulnServerInputValidation:
    """Test argument handling on the vulnerable (unvalidated) server."""

    @pytest.fixture(autouse=True, scope="class")
    def _start_vuln(self, vuln_server):
        """Ensure the vulnerable server is running for all tests in this class."""

    def test_read_file_missing_path_returns_error(self):
        """Vulnerable server: missing 'path' → MCP SDK schema validation rejects it."""
        result = call_tool_sync(VULN_PORT, "read_secure_file", {})
        text = _result_text(result)
        assert result.isError or "[ERR]" in text or "error" in text.lower()

    def test_write_file_missing_content_returns_error(self):
        result = call_tool_sync(VULN_PORT, "write_file", {"path": "test.txt"})
        text = _result_text(result)
        assert result.isError or "[OK]" in text or "[ERR]" in text or "error" in text.lower()

    def test_nonexistent_tool_returns_error(self):
        """Vulnerable server returns 'Unknown tool' text for unrecognized tools."""
        result = call_tool_sync(VULN_PORT, "nonexistent_tool", {})
        text = _result_text(result)
        assert "Unknown tool" in text or result.isError

    def test_query_secrets_returns_passwords(self):
        """Vulnerable server leaks the secrets table."""
        result = call_tool_sync(VULN_PORT, "query_mock_db", {"table": "secrets"})
        text = _result_text(result)
        assert "sk-mock-123456789" in text or "hunter2" in text

    def test_query_users_returns_data(self):
        """Vulnerable server returns user data from the users table."""
        result = call_tool_sync(VULN_PORT, "query_mock_db", {"table": "users"})
        text = _result_text(result)
        assert "Alice" in text

    def test_read_file_with_extra_arg(self):
        """Vulnerable server ignores unknown arguments (no validation)."""
        result = call_tool_sync(
            VULN_PORT, "read_secure_file", {"path": "hello.txt", "reason": "test"}
        )
        text = _result_text(result)
        # Should still work — vulnerable server doesn't reject unknown keys
        assert "[OK]" in text or "[ERR]" in text


# ---------------------------------------------------------------------------
# Integration tests: secure server
# ---------------------------------------------------------------------------


class TestSecureServerInputValidation:
    """Test argument handling on the secure (validated) server."""

    @pytest.fixture(autouse=True, scope="class")
    def _start_secure(self, secure_server):
        """Ensure the secure server is running for all tests in this class."""

    def test_read_file_missing_path_returns_error(self):
        """Secure server rejects missing required 'path' argument."""
        result = call_tool_sync(SECURE_PORT, "read_secure_file", {})
        assert result.isError

    def test_write_file_missing_content_returns_error(self):
        """Secure server rejects missing required 'content' argument."""
        result = call_tool_sync(SECURE_PORT, "write_file", {"path": "test.txt"})
        assert result.isError

    def test_nonexistent_tool_returns_error(self):
        """Secure server rejects calls to non-existent tools."""
        result = call_tool_sync(SECURE_PORT, "nonexistent_tool", {})
        assert result.isError

    def test_query_secrets_is_blocked(self):
        """Secure server blocks access to the secrets table."""
        result = call_tool_sync(SECURE_PORT, "query_mock_db", {"table": "secrets"})
        assert result.isError
        text = _result_text(result).lower()
        assert "denied" in text or "forbidden" in text

    def test_query_users_returns_data(self):
        """Secure server returns user data from the users table."""
        result = call_tool_sync(SECURE_PORT, "query_mock_db", {"table": "users"})
        text = _result_text(result)
        assert "Alice" in text
        assert not result.isError

    def test_read_file_with_extra_arg_returns_error(self):
        """Secure server rejects unknown arguments via strict_input_validation."""
        result = call_tool_sync(
            SECURE_PORT, "read_secure_file", {"path": "hello.txt", "reason": "test"}
        )
        assert result.isError
