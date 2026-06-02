"""Raw JSON packet capturer and formatter for MCP telemetry inspection."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Global capture buffer; can be flushed to disk or stdout.
_capture_buffer: list[dict[str, Any]] = []
_LOG_PATH = Path(__file__).with_suffix(".log.jsonl")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_packet(direction: str, payload: dict[str, Any] | str) -> None:
    """Log a single JSON-RPC packet with metadata.

    Args:
        direction: 'inbound' (client→server) or 'outbound' (server→client).
        payload: The raw JSON payload. Strings are parsed if possible.
    """
    if isinstance(payload, str):
        try:
            body = json.loads(payload)
        except json.JSONDecodeError:
            body = {"_raw": payload}
    else:
        body = payload

    entry = {
        "timestamp": _now(),
        "direction": direction,
        "method": body.get("method") if isinstance(body, dict) else None,
        "id": body.get("id") if isinstance(body, dict) else None,
        "payload": body,
    }

    _capture_buffer.append(entry)

    # Pretty-print to stdout for live telemetry inspection.
    print(f"\n[TELEMETRY] {direction.upper()} | {_now()}", file=sys.stderr)
    print(json.dumps(entry, indent=2, ensure_ascii=False), file=sys.stderr)

    # Append to JSONL log for downstream analysis.
    with open(_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def flush() -> Path:
    """Flush the in-memory buffer to a JSONL file and return the path."""
    if not _capture_buffer:
        return _LOG_PATH

    # Write atomically to a timestamped snapshot.
    snapshot = Path(__file__).parent / f"mcp_telemetry_{_now().replace(':', '-')}.jsonl"
    with open(snapshot, "w", encoding="utf-8") as fh:
        for entry in _capture_buffer:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    _capture_buffer.clear()
    return snapshot


def get_captured_packets() -> list[dict[str, Any]]:
    """Return a shallow copy of the current capture buffer."""
    return list(_capture_buffer)
