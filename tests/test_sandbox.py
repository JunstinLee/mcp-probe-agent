"""Tests for the lightweight process sandbox (unshare/subprocess-based isolation)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.security.sandbox_driver import SandboxDriver


class TestSandboxDriver:
    """Tests for SandboxDriver process lifecycle."""

    def test_sandbox_dir_default(self):
        driver = SandboxDriver()
        assert driver.sandbox_dir == Path("/tmp/mcp_sandbox_secure")

    def test_sandbox_dir_custom(self):
        custom = Path("/tmp/custom_sandbox")
        driver = SandboxDriver(sandbox_dir=custom)
        assert driver.sandbox_dir == custom

    def test_start_stop_cycle(self):
        """Start and stop a sandboxed server process."""
        driver = SandboxDriver()
        # This test requires the sandbox directory and probe_server_secure.py to exist.
        # Skip if sandbox is not initialized.
        if not driver.sandbox_dir.exists():
            pytest.skip("Sandbox directory not initialized")

        proc = driver.start(port=9876, network=False)
        assert proc.poll() is None, "Sandbox process should be running"

        driver.stop(proc)
        assert proc.poll() is not None, "Sandbox process should have exited"

    def test_network_isolation_flag(self):
        """Verify that network=False prepends unshare to the command."""
        driver = SandboxDriver()
        # We inspect the internal command construction by mocking Popen
        recorded_cmd = None

        original_popen = subprocess.Popen

        def mock_popen(cmd, **kwargs):
            nonlocal recorded_cmd
            recorded_cmd = cmd
            # Return a mock-like object
            class FakeProc:
                def poll(self):
                    return None
                def terminate(self):
                    pass
                def wait(self, timeout=None):
                    return 0
            return FakeProc()

        subprocess.Popen = mock_popen
        try:
            driver.start(port=8766, network=False)
            assert recorded_cmd is not None
            assert recorded_cmd[0] == "unshare"
            assert "--net" in recorded_cmd
        finally:
            subprocess.Popen = original_popen

    def test_network_allowed_flag(self):
        """Verify that network=True does NOT prepend unshare."""
        driver = SandboxDriver()
        recorded_cmd = None
        original_popen = subprocess.Popen

        def mock_popen(cmd, **kwargs):
            nonlocal recorded_cmd
            recorded_cmd = cmd
            class FakeProc:
                def poll(self):
                    return None
                def terminate(self):
                    pass
                def wait(self, timeout=None):
                    return 0
            return FakeProc()

        subprocess.Popen = mock_popen
        try:
            driver.start(port=8766, network=True)
            assert recorded_cmd is not None
            assert recorded_cmd[0] == "python"
        finally:
            subprocess.Popen = original_popen


class TestSandboxScripts:
    """Tests for the shell-based sandbox scripts."""

    def test_init_sandbox_exists(self):
        script = Path("scripts/init_sandbox.sh")
        assert script.exists(), f"{script} should exist"
        assert script.stat().st_mode & 0o111, f"{script} should be executable"

    def test_run_sandbox_exists(self):
        script = Path("scripts/run_sandbox.sh")
        assert script.exists(), f"{script} should exist"
        assert script.stat().st_mode & 0o111, f"{script} should be executable"
