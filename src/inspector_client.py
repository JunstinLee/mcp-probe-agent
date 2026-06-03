"""
Host Client — Automated attack orchestrator against the secure MCP server.

Usage:
    python src/inspector_client.py

The client:
1. Loads exploit payloads from exploits/payloads.json.
2. Connects to the secure MCP server via SSE.
3. Executes each payload and records actual vs expected outcomes.
4. Writes a structured JSON report to output/<timestamp>/attack_report.json.
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import json
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession, types
from mcp.client.sse import sse_client

from logger import flush, get_run_dir, log_packet
from security.dlp_scanner import scan_text
from security.token_budget import SessionBudget

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECURE_PORT = 8766

PAYLOADS_PATH = Path(__file__).resolve().parent.parent / "exploits" / "payloads.json"


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
    async with sse_client(url, headers={"Authorization": "Bearer test-api-key"}) as (read_stream, write_stream):
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


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    results: list[dict[str, Any]],
) -> Path:
    """Write a JSON report with timestamp, results, and summary into the run directory."""
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

    report_text = json.dumps(report, ensure_ascii=False)
    masked, detected = scan_text(report_text)
    if detected:
        print(f"[DLP] ⚠️ 报告输出中发现敏感字段: {detected}")

    output_path = get_run_dir() / "attack_report.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(masked)

    print(f"[ORCHESTRATOR] Report written to {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Network-layer checks (bypass SSE session)
# ---------------------------------------------------------------------------

def _test_message_endpoint_auth(port: int) -> tuple[str, str]:
    """POST to /message without Authorization; return (outcome, details)."""
    conn = http.client.HTTPConnection("127.0.0.1", port)
    try:
        conn.request(
            "POST",
            "/message",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        if response.status == 401:
            return "blocked", f"HTTP {response.status}: {response.reason}"
        return "leaked", f"HTTP {response.status}: {response.reason}"
    except Exception as exc:
        return "error", f"HTTP request failed: {exc}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def _run_payloads_against_server(
    payloads: list[dict[str, Any]],
    port: int,
    server_label: str,
    budget: SessionBudget,
) -> list[dict[str, Any]]:
    """Run *payloads* against a single server, returning result dicts."""
    results: list[dict[str, Any]] = []

    try:
        async with connect_server(port) as session:
            for payload in payloads:
                try:
                    if budget.is_exhausted():
                        raise RuntimeError(
                            f"Budget exhausted: turns={budget.turn_count}, "
                            f"tokens={budget.estimated_tokens}"
                        )
                    # Special-case: test /message endpoint without Bearer token
                    if payload.get("name") == "Missing Bearer token on message endpoint":
                        actual, details = _test_message_endpoint_auth(port)
                        passed = actual == payload["expected_outcome"]
                        entry = {
                            "payload_name": payload["name"],
                            "target_server": server_label,
                            "expected_outcome": payload["expected_outcome"],
                            "actual_outcome": actual,
                            "passed": passed,
                            "details": details,
                        }
                        results.append(entry)
                        status = "PASS" if passed else "FAIL"
                        print(
                            f"  [{status}] {payload['name']} ({server_label}): "
                            f"expected={payload['expected_outcome']}, "
                            f"actual={actual}"
                        )
                        budget.record_turn()
                        continue

                    result = await execute_attack(session, payload)
                    entry = _evaluate_result(result, payload, server_label)
                    results.append(entry)
                    status = "PASS" if entry["passed"] else "FAIL"
                    print(
                        f"  [{status}] {payload['name']} ({server_label}): "
                        f"expected={entry['expected_outcome']}, "
                        f"actual={entry['actual_outcome']}"
                    )
                    budget.record_turn()
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


async def orchestrate() -> None:
    """Run all secure-target payloads against the secure server."""
    payloads = load_payloads("secure")
    budget = SessionBudget()
    print(
        f"[ORCHESTRATOR] Running {len(payloads)} payloads "
        f"against SECURE server (port {SECURE_PORT})"
    )
    results = await _run_payloads_against_server(
        payloads, SECURE_PORT, "secure", budget
    )
    report_path = generate_report(results)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    s = report["summary"]
    print(
        f"\n[ORCHESTRATOR] Summary: {s['passed']}/{report['total_payloads']} passed, "
        f"{s['failed']} failed"
    )

    flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Attack Orchestrator — Automated security testing against secure server"
    )
    args = parser.parse_args()

    try:
        asyncio.run(orchestrate())
    except KeyboardInterrupt:
        print("\n[ORCHESTRATOR] Interrupted by user.")
    except Exception as exc:
        print(f"\n[ORCHESTRATOR] Fatal error: {exc}")
        raise


if __name__ == "__main__":
    main()