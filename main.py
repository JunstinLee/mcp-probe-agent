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
import sys

from src.cli.commands import cmd_attack, cmd_clean, cmd_run_secure, cmd_run_vuln, cmd_test


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
