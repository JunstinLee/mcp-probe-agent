"""
Tests for multi-tenant sandbox isolation.
Verifies that files written by one user are not accessible by another.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.validators import validate_sandbox_path


class TestMultiTenantIsolation:
    """Tests for per-user sandbox directory isolation."""

    @pytest.fixture
    def user_a_sandbox(self, tmp_path: Path) -> Path:
        return tmp_path / "user_a"

    @pytest.fixture
    def user_b_sandbox(self, tmp_path: Path) -> Path:
        return tmp_path / "user_b"

    def test_user_a_file_not_visible_to_user_b(self, user_a_sandbox, user_b_sandbox):
        """User A writes a file; User B cannot read it via path traversal."""
        user_a_sandbox.mkdir(parents=True, exist_ok=True)
        user_b_sandbox.mkdir(parents=True, exist_ok=True)

        secret_file = user_a_sandbox / "secret.txt"
        secret_file.write_text("User A's secret data")

        # User B attempts to access User A's file via traversal
        with pytest.raises(ValueError, match="path escapes sandbox"):
            validate_sandbox_path("../user_a/secret.txt", str(user_b_sandbox))

    def test_user_a_cannot_write_to_user_b_sandbox(self, user_a_sandbox, user_b_sandbox):
        """User A cannot use path traversal to write into User B's sandbox."""
        user_a_sandbox.mkdir(parents=True, exist_ok=True)
        user_b_sandbox.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="path escapes sandbox"):
            validate_sandbox_path("../user_b/malicious.txt", str(user_a_sandbox))

    def test_same_filename_isolated_per_user(self, tmp_path: Path):
        """Two users can have files with the same name without collision."""
        user_a_sandbox = tmp_path / "user_a"
        user_b_sandbox = tmp_path / "user_b"
        user_a_sandbox.mkdir(parents=True, exist_ok=True)
        user_b_sandbox.mkdir(parents=True, exist_ok=True)

        file_a = user_a_sandbox / "data.txt"
        file_b = user_b_sandbox / "data.txt"
        file_a.write_text("Data for A")
        file_b.write_text("Data for B")

        assert file_a.read_text() == "Data for A"
        assert file_b.read_text() == "Data for B"

    def test_absolute_path_traversal_blocked(self, user_a_sandbox):
        """Absolute paths attempting to escape the sandbox are rejected."""
        user_a_sandbox.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="path escapes sandbox"):
            validate_sandbox_path("/etc/passwd", str(user_a_sandbox))

    def test_nested_traversal_between_users_blocked(self, user_a_sandbox, user_b_sandbox):
        """Deeply nested traversal from one user sandbox to another is blocked."""
        user_a_sandbox.mkdir(parents=True, exist_ok=True)
        user_b_sandbox.mkdir(parents=True, exist_ok=True)

        with pytest.raises(ValueError, match="path escapes sandbox"):
            validate_sandbox_path(
                "subdir/../../../../../user_b/secret.txt",
                str(user_a_sandbox),
            )

    def test_per_user_sandbox_creation(self, tmp_path: Path):
        """Sandbox directories for different users are distinct paths."""
        base = tmp_path / "mcp_sandbox"
        sandbox_a = base / "alice"
        sandbox_b = base / "bob"

        assert sandbox_a != sandbox_b
        assert str(sandbox_a).startswith(str(base))
        assert str(sandbox_b).startswith(str(base))

    def test_sandbox_enforced_for_each_user(self, tmp_path: Path):
        """Each user's sandbox path is validated independently."""
        alice_sandbox = tmp_path / "sandbox_alice"
        alice_sandbox.mkdir(parents=True, exist_ok=True)
        (alice_sandbox / "file.txt").write_text("alice content")

        # Path within Alice's sandbox should succeed
        result = validate_sandbox_path("file.txt", str(alice_sandbox))
        assert result == (alice_sandbox / "file.txt").resolve()
