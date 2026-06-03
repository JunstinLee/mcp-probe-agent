"""
Pure-function validators for MCP probe agent security checks.
No classes, no logging — callers handle errors.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Shell metacharacter guard (shared across validators)
# ---------------------------------------------------------------------------

_SHELL_META_RE = re.compile(r"[;|&$`\\n<>{}\\\[\\]]")


def _reject_shell_meta(value: str, field_name: str = "path") -> None:
    """Raise ValueError if `value` contains shell metacharacters."""
    if _SHELL_META_RE.search(value):
        raise ValueError(f"{field_name} contains shell metacharacters")


# ---------------------------------------------------------------------------
# validate_sandbox_path
# ---------------------------------------------------------------------------


def validate_sandbox_path(path: str, sandbox_dir: str) -> Path:
    """
    Validate that `path` resolves to a location inside `sandbox_dir`.

    Security checks (in order):
        1. Reject shell metacharacters in the path string.
        2. Reject null bytes in the path string.
        3. Resolve `sandbox_dir` once as the canonical base.
        4. Join `path` with `sandbox_dir`, then resolve.
        5. Verify the resolved path starts with the sandbox_dir prefix.
        6. Reject symbolic links (potential symlink attacks).
        7. Return the resolved Path object.

    Raises ValueError if any check fails.
    """
    # 1. Reject shell metacharacters
    _reject_shell_meta(path)

    # 2. Reject null bytes
    if "\0" in path:
        raise ValueError("path contains null byte")

    # 3. Resolve sandbox_dir once
    sandbox_path = Path(sandbox_dir).resolve()

    # 3. Join and resolve target path
    target_path = Path(os.path.join(sandbox_dir, path)).resolve()

    # 4. Prefix check — ensure target is under sandbox
    if not target_path.is_relative_to(sandbox_path):
        raise ValueError("path escapes sandbox")

    # 5. Reject symlinks
    if os.path.islink(target_path):
        raise ValueError("path is a symbolic link")

    # 6. Return resolved Path
    return target_path


# ---------------------------------------------------------------------------
# sanitize_output
# ---------------------------------------------------------------------------


_INJECTION_RE = re.compile(
    r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|before)\s+(instructions?|directives?|prompts?)",
    re.DOTALL,
)

_DELIMITER_RE = re.compile(r"(?i)```system.*?```", re.DOTALL)


def sanitize_output(text: str) -> str:
    """
    Remove prompt-injection patterns from LLM-generated output and wrap
    the result in <tool_output> delimiters.

    Replacements:
        - Injection directives matching INJECTION_RE  → "[FILTERED]"
        - System-delimiter blocks matching DELIMITER_RE → "[FILTERED-DELIMITER]"

    The sanitized text is wrapped in <tool_output>\\n...\\n</tool_output>.
    """
    filtered = _INJECTION_RE.sub("[FILTERED]", text)
    filtered = _DELIMITER_RE.sub("[FILTERED-DELIMITER]", filtered)
    return f"<tool_output>\n{filtered}\n</tool_output>"


# ---------------------------------------------------------------------------
# validate_required_args
# ---------------------------------------------------------------------------


def validate_required_args(args: dict, required: list[str], allowed: list[str]) -> dict:
    """
    Validate that `args` contains all `required` keys with non-empty values
    and contains no unknown keys outside `allowed`.

    Returns a filtered dict containing only the keys in `allowed` that are
    present in `args`.

    Raises ValueError if:
        - A required key is missing or empty.
        - An unknown key (not in `allowed`) is present.
    """
    # Check for unknown keys
    unknown = set(args.keys()) - set(allowed)
    if unknown:
        raise ValueError(f"unknown arguments: {', '.join(sorted(unknown))}")

    # Check required keys
    for key in required:
        if key not in args or not args[key]:
            raise ValueError(f"missing required argument: {key}")

    # Return filtered args
    return {k: args[k] for k in allowed if k in args}


# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------

_BLOCKED_HOST_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)",
)


def validate_url(url: str) -> None:
    """
    Reject URLs that point to private/internal networks or cloud metadata endpoints.

    Raises ValueError if the host matches a blocked prefix.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if _BLOCKED_HOST_RE.match(host):
        raise ValueError(f"access to internal address {host} is forbidden")