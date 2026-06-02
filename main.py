"""Unified CLI entrypoint for mcp-probe-agent.

Commands:
    run-vuln    Start the vulnerable MCP server (port 8765)
    run-secure  Start the secure MCP server (port 8766)
    attack      Run the attack orchestrator
    test        Run the pytest test suite
    clean       Remove temporary sandbox and log files
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _python() -> list[str]:
    return [sys.executable]


def cmd_run_vuln() -> None:
    """Start the vulnerable MCP server."""
    print("[CLI] Starting vulnerable MCP server on port 8765 ...")
    os.makedirs("/tmp/mcp_sandbox", exist_ok=True)
    subprocess.run([*_python(), "src/probe_server.py"], check=False)


def cmd_run_secure() -> None:
    """Start the secure MCP server."""
    print("[CLI] Starting secure MCP server on port 8766 ...")
    os.makedirs("/tmp/mcp_sandbox_secure", exist_ok=True)
    subprocess.run([*_python(), "src/probe_server_secure.py"], check=False)


def cmd_attack(args: argparse.Namespace) -> None:
    """Run the attack orchestrator."""
    target = args.target or "both"
    print(f"[CLI] Running attack orchestrator --target={target} ...")
    subprocess.run(
        [*_python(), "src/inspector_client.py", "--target", target],
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
    """Remove temporary sandbox directories and log files."""
    paths: list[Path] = [
        Path("/tmp/mcp_sandbox"),
        Path("/tmp/mcp_sandbox_secure"),
    ]
    src = Path(__file__).resolve().parent / "src"
    for pattern in ["*.log.jsonl", "mcp_telemetry_*.jsonl", "attack_report.json"]:
        paths.extend(src.glob(pattern))

    for p in paths:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            print(f"[CLEAN] Removed directory: {p}")
        elif p.is_file():
            p.unlink(missing_ok=True)
            print(f"[CLEAN] Removed file: {p}")

    print("[CLEAN] Done.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="mcp-probe-agent — MCP security sandbox CLI",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    p_run_vuln = sub.add_parser("run-vuln", help="Start vulnerable MCP server (port 8765)")
    p_run_vuln.set_defaults(func=lambda _: cmd_run_vuln())

    p_run_secure = sub.add_parser("run-secure", help="Start secure MCP server (port 8766)")
    p_run_secure.set_defaults(func=lambda _: cmd_run_secure())

    p_attack = sub.add_parser("attack", help="Run attack orchestrator")
    p_attack.add_argument(
        "--target",
        choices=["vulnerable", "secure", "both"],
        default="both",
        help="Target server(s) to attack (default: both)",
    )
    p_attack.set_defaults(func=cmd_attack)

    p_test = sub.add_parser("test", help="Run pytest test suite")
    p_test.set_defaults(func=lambda _: cmd_test())

    p_clean = sub.add_parser("clean", help="Remove temporary sandbox/log files")
    p_clean.set_defaults(func=lambda _: cmd_clean())

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
