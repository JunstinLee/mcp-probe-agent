"""
Host Client simulating LLM tool-calling orchestration over SSE transport.

Run with (after probe_server.py is up):
    python src/inspector_client.py

The client:
1. Connects to the server's SSE endpoint.
2. Lists available tools.
3. Executes a sequence of calls (including exploit payloads) to audit behavior.
4. Prints raw JSON-RPC telemetry for inspection.
"""

from __future__ import annotations

import asyncio

from mcp import types
from mcp import ClientSession
from mcp.client.sse import sse_client

from src.logger import flush, log_packet

SERVER_URL = "http://127.0.0.1:8765/sse"


def _text(result: types.CallToolResult) -> str:
    first = result.content[0]
    if isinstance(first, types.TextContent):
        return first.text
    return str(first)


async def inspect() -> None:
    print(f"[INSPECTOR] Connecting to {SERVER_URL} ...")

    async with sse_client(SERVER_URL) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            print(f"[INSPECTOR] Server initialized: {init_result.serverInfo.name} v{init_result.serverInfo.version}")

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


if __name__ == "__main__":
    try:
        asyncio.run(inspect())
    except KeyboardInterrupt:
        print("\n[INSPECTOR] Interrupted by user.")
    except Exception as exc:
        print(f"\n[INSPECTOR] Fatal error: {exc}")
        raise
