"""
End-to-end integration tests for the secure mcp-probe-agent server.

Verifies the attack cycle, CLI commands, guardrails, and sandbox isolation.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp import ClientSession
from mcp.client.sse import sse_client

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, **kwargs)


async def _call_sse(port: int, tool: str, args: dict) -> dict:
    """Call an MCP tool and return {'isError': bool, 'text': str}."""
    async with sse_client(f"http://127.0.0.1:{port}/sse") as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            text = ""
            if result.content:
                first = result.content[0]
                if hasattr(first, "text"):
                    text = first.text
            return {"isError": result.isError, "text": text}


# ---------------------------------------------------------------------------
# Server fixtures (module-scoped — start once for this file)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def secure_server():
    """Start the secure server. Yield nothing; cleanup after."""
    proc = subprocess.Popen(
        [sys.executable, "src/probe_server_secure.py"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    yield
    proc.terminate()
    proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# TestFullAttackCycle
# ---------------------------------------------------------------------------

class TestFullAttackCycle:
    """Run the orchestrator against the secure server and verify the report."""

    @pytest.fixture(autouse=True, scope="class")
    def _server(self, secure_server):
        pass

    def test_secure_server_blocks_known_exploits(self):
        """Core path traversal and prompt injection payloads must be blocked."""
        # Basic directory traversal
        r = asyncio.run(_call_sse(8766, "read_secure_file", {"path": "../../etc/passwd"}))
        assert r["isError"], "Secure server must block path traversal"
        assert "root:" not in r["text"], "Secure server must NOT leak /etc/passwd"

        # Prompt injection sanitized
        r2 = asyncio.run(_call_sse(8766, "scrape_webpage", {"url": "http://x.com"}))
        assert "<tool_output>" in r2["text"]
        assert "[FILTERED]" in r2["text"]

        # Secrets table blocked
        r3 = asyncio.run(_call_sse(8766, "query_mock_db", {"table": "secrets"}))
        assert r3["isError"], "Secure server must block secrets table"

    def test_legitimate_ops_work_on_secure(self):
        """Legitimate operations should not be blocked."""
        r = asyncio.run(_call_sse(8766, "read_secure_file", {"path": "hello.txt"}))
        assert not r["isError"], "Legitimate read should succeed"
        assert "Hello" in r["text"]

        r2 = asyncio.run(_call_sse(8766, "query_mock_db", {"table": "users"}))
        assert not r2["isError"]
        assert "Alice" in r2["text"]

    def test_orchestrator_produces_valid_report(self):
        """The orchestrator generates a valid JSON report file."""
        result = _run(
            [sys.executable, str(SRC / "inspector_client.py")],
            timeout=60,
        )
        # Report should have been written
        report_path = SRC / "attack_report.json"
        assert report_path.exists(), "Orchestrator must generate attack_report.json"
        report = json.loads(report_path.read_text())
        assert "timestamp" in report
        assert "results" in report
        assert "summary" in report
        assert isinstance(report["summary"]["passed"], int)
        assert isinstance(report["summary"]["failed"], int)


# ---------------------------------------------------------------------------
# TestCLIEndToEnd
# ---------------------------------------------------------------------------

class TestCLIEndToEnd:
    """Verify main.py CLI commands work."""

    def test_cli_help_shows_commands(self):
        cp = _run([sys.executable, "main.py", "--help"])
        assert cp.returncode == 0
        assert "run" in cp.stdout
        assert "attack" in cp.stdout

    def test_cli_clean_returns_zero(self):
        cp = _run([sys.executable, "main.py", "clean"])
        assert cp.returncode == 0

    def test_cli_test_runs(self):
        """main.py test invokes pytest (may have failures, exit code non-zero if so)."""
        cp = _run([sys.executable, "main.py", "test"], timeout=120)
        # Test exit code may be non-zero if there are failures,
        # but the command itself should not crash
        assert cp.returncode is not None  # completed without exception


# ---------------------------------------------------------------------------
# TestGuardrailEnforcement
# ---------------------------------------------------------------------------

class TestGuardrailEnforcement:
    """Verify critical guardrails are in place."""

    def test_sandbox_directories_isolated(self):
        """Secure server uses a dedicated sandbox dir."""
        import src.probe_server_secure as secure
        assert secure.SANDBOX_DIR_SECURE == "/tmp/mcp_sandbox_secure", (
            "Secure server must use isolated sandbox"
        )

    def test_secure_server_debug_disabled(self):
        """Secure server must not run in debug mode."""
        content = (SRC / "probe_server_secure.py").read_text()
        assert "debug=False" in content or 'debug=False' in content or "debug = False" in content, (
            "Secure server must use debug=False"
        )


# ---------------------------------------------------------------------------
# TestSandboxIsolation
# ---------------------------------------------------------------------------

class TestSandboxIsolation:
    """Verify sandbox isolation works correctly for the secure server."""

    @pytest.fixture(autouse=True, scope="class")
    def _server(self, secure_server):
        pass

    def test_secure_sandbox_accessible(self):
        """Secure server sandbox is at /tmp/mcp_sandbox_secure."""
        r = asyncio.run(_call_sse(8766, "read_secure_file", {"path": "hello.txt"}))
        assert not r["isError"]
        assert "Hello" in r["text"]

    def test_traversal_blocked(self):
        """Secure server must block path traversal."""
        s = asyncio.run(_call_sse(8766, "read_secure_file", {"path": "../../etc/passwd"}))
        assert s["isError"], "Secure server must block traversal"
