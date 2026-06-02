"""Raw JSON packet capturer and formatter for MCP telemetry inspection."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Output directory management
# ---------------------------------------------------------------------------

_OUTPUT_BASE = Path(__file__).resolve().parent.parent / "output"
_run_dir: Path | None = None


def get_run_dir() -> Path:
    """Return (and create if needed) a timestamped sub-directory under output/."""
    global _run_dir
    if _run_dir is None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        _run_dir = _OUTPUT_BASE / ts
        _run_dir.mkdir(parents=True, exist_ok=True)
    return _run_dir


def reset_run_dir() -> None:
    """Reset the run directory so the next call to get_run_dir() creates a fresh one."""
    global _run_dir
    _run_dir = None


# ---------------------------------------------------------------------------
# Logging internals
# ---------------------------------------------------------------------------

_capture_buffer: list[dict[str, Any]] = []

# Level constants
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_DEFAULT_LEVEL = 10  # DEBUG


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_sensitive(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively replace sensitive field values with [REDACTED]."""
    sensitive_pattern = re.compile(
        r"(api[_-]?key|password|secret|token)",
        re.IGNORECASE
    )
    result = {}
    for key, value in payload.items():
        if sensitive_pattern.search(key):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = _redact_sensitive(value)
        elif isinstance(value, list):
            result[key] = [
                _redact_sensitive(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    return result


def _rotate_if_needed(log_path: Path, max_size: int = 10 * 1024 * 1024) -> None:
    """Rotate log file if it exceeds max_size, keeping up to 3 backups."""
    if not log_path.exists():
        return
    if log_path.stat().st_size < max_size:
        return
    if Path(str(log_path) + ".3").exists():
        Path(str(log_path) + ".3").unlink()
    if Path(str(log_path) + ".2").exists():
        shutil.move(str(log_path) + ".2", str(log_path) + ".3")
    if Path(str(log_path) + ".1").exists():
        shutil.move(str(log_path) + ".1", str(log_path) + ".2")
    shutil.copy2(log_path, str(log_path) + ".1")
    with open(log_path, "w", encoding="utf-8") as fh:
        pass


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

    if os.environ.get("MCP_LOG_REDACT") == "1":
        entry = _redact_sensitive(entry)

    _capture_buffer.append(entry)

    log_level_str = os.environ.get("MCP_LOG_LEVEL", "DEBUG").upper()
    log_level = _LEVELS.get(log_level_str, _DEFAULT_LEVEL)
    effective_level = _LEVELS["WARN"] if (entry.get("method", "") or "").startswith("error") else _LEVELS["DEBUG"]

    if effective_level >= log_level:
        print(f"\n[TELEMETRY] {direction.upper()} | {_now()}", file=sys.stderr)
        print(json.dumps(entry, indent=2, ensure_ascii=False), file=sys.stderr)

    log_path = get_run_dir() / "mcp_telemetry.jsonl"
    _rotate_if_needed(log_path)

    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def flush() -> Path:
    """Flush the in-memory buffer to a JSONL file inside the run directory."""
    if not _capture_buffer:
        return get_run_dir()

    snapshot = get_run_dir() / "mcp_telemetry_snapshot.jsonl"
    with open(snapshot, "w", encoding="utf-8") as fh:
        for entry in _capture_buffer:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    _capture_buffer.clear()
    return snapshot


def get_captured_packets() -> list[dict[str, Any]]:
    """Return a shallow copy of the current capture buffer."""
    return list(_capture_buffer)
