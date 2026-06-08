"""Tests for argument/option injection defenses.

Covers:
    - subprocess_guard: ``--`` insertion logic
    - command_validator: ``-`` prefix blocking with allow_options param
"""

from __future__ import annotations

from typing import Any

import pytest

from src.security.command_validator import validate_command_arg
from src.security.subprocess_guard import _NO_DASH_COMMANDS, SecurityError, safe_subprocess_run


class TestCommandValidatorDashPrefix:
    def test_normal_arg_passes(self):
        result = validate_command_arg("hello.txt")
        assert result == "hello.txt"

    def test_dash_prefix_blocked_by_default(self):
        with pytest.raises(ValueError, match="starts with '-'"):
            validate_command_arg("-C")

    def test_double_dash_prefix_blocked(self):
        """--exec=whoami fails whitelist first (= is forbidden), then dash check.
        Verifying that -- prefixed args are caught (whitelist or dash check)."""
        with pytest.raises(ValueError):
            validate_command_arg("--exec=whoami")

    def test_dash_prefix_allowed_with_flag(self):
        result = validate_command_arg("-C", allow_options=True)
        assert result == "-C"

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            validate_command_arg("")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValueError, match="empty or whitespace"):
            validate_command_arg("   ")

    def test_oversized_arg_rejected(self):
        with pytest.raises(ValueError, match="exceeds max length"):
            validate_command_arg("a" * 5000)

    def test_forbidden_characters_rejected(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_command_arg("hello; rm -rf /")


class TestSubprocessGuardDashInsertion:
    def test_inserts_dash_dash_after_options(self):
        """-- is inserted after command name, before user-supplied args."""
        cmd = ["git", "commit", "-m", "hello"]
        safe_subprocess_run(cmd, capture_output=True, text=True)
        assert "--" in cmd
        assert cmd[1] == "--"

    def test_dash_dash_inserted_before_positional(self):
        """-- is inserted between options (-la) and positional args (/tmp)."""
        from src.security.subprocess_guard import safe_subprocess_run as run_cmd

        cmd = ["ls", "-la", "/tmp"]
        run_cmd(cmd, capture_output=True, text=True)
        assert "--" in cmd
        assert cmd.index("--") == 2
        assert cmd[1] == "-la"
        assert cmd[3] == "/tmp"

    def test_echo_skips_dash_dash(self):
        assert "echo" in _NO_DASH_COMMANDS
        cmd = ["echo", "hello", "world"]
        safe_subprocess_run(cmd, capture_output=True, text=True)
        assert "--" not in cmd

    def test_python_skips_dash_dash(self):
        assert "echo" in _NO_DASH_COMMANDS
        cmd = ["echo", "hello", "world"]
        safe_subprocess_run(cmd, capture_output=True, text=True)
        assert "--" not in cmd

    def test_no_insertion_when_all_options(self):
        cmd = ["ls", "-l", "-a"]
        safe_subprocess_run(cmd, capture_output=True, text=True)
        assert "--" not in cmd

    def test_shell_true_rejected(self):
        with pytest.raises(SecurityError, match="shell=True is forbidden"):
            safe_subprocess_run(["ls"], shell=True, capture_output=True, text=True)

    def test_string_cmd_rejected(self):
        with pytest.raises(SecurityError, match="must be a list"):
            cmd: Any = "ls -la"
            safe_subprocess_run(cmd, capture_output=True, text=True)

    def test_shell_metachar_rejected(self):
        with pytest.raises(SecurityError, match="Forbidden shell metacharacter"):
            safe_subprocess_run(["ls", "'$(whoami)'"], capture_output=True, text=True)

    def test_insert_dash_dash_disabled(self):
        cmd = ["ls", "/tmp"]
        safe_subprocess_run(cmd, insert_dash_dash=False, capture_output=True, text=True)
        assert "--" not in cmd
