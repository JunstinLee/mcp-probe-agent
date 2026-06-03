"""Command implementations for mcp-probe-agent CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _python() -> list[str]:
    return [sys.executable]


def cmd_run() -> None:
    """Start the secure MCP server."""
    print("[CLI] Starting secure MCP server on port 8766 ...")
    os.makedirs("/tmp/mcp_sandbox_secure", exist_ok=True)
    subprocess.run([*_python(), "src/probe_server_secure.py"], check=False)


def cmd_attack() -> None:
    """Run the attack orchestrator."""
    print("[CLI] Running attack orchestrator ...")
    subprocess.run(
        [*_python(), "src/inspector_client.py"],
        check=False,
    )


def cmd_test() -> None:
    """Run the pytest test suite."""
    print("[CLI] Running tests ...")
    result = subprocess.run(
        [*_python(), "-m", "pytest", "tests/", "-v"],
        check=False,
    )
    sys.exit(result.returncode)


def cmd_clean() -> None:
    """Remove temporary sandbox directories, log files, and output directory."""
    paths: list[Path] = [
        Path("/tmp/mcp_sandbox_secure"),
    ]

    # Legacy src/ files
    src = Path(__file__).resolve().parent.parent
    for pattern in ["*.log.jsonl", "mcp_telemetry_*.jsonl", "attack_report.json"]:
        paths.extend(src.glob(pattern))

    # New output/ directory
    output_dir = src.parent / "output"
    if output_dir.exists():
        paths.append(output_dir)

    for p in paths:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            print(f"[CLEAN] Removed directory: {p}")
        elif p.is_file():
            p.unlink(missing_ok=True)
            print(f"[CLEAN] Removed file: {p}")

    print("[CLEAN] Done.")
