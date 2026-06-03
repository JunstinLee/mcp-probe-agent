"""
Subprocess guard — hardened wrapper around subprocess.run.

Enforces:
    - shell=True is strictly forbidden
    - Arguments must be passed as list[str] (no string concatenation)
    - Shell metacharacters are rejected in every argument
"""

from __future__ import annotations

import re
import subprocess
from typing import Any


class SecurityError(ValueError):
    """Raised when a security policy violation is detected in subprocess usage."""

    pass


# ---------------------------------------------------------------------------
# Shell metacharacter blacklist
# ---------------------------------------------------------------------------

_SHELL_META_RE = re.compile(r"[;|&$`\\n<>{}\\\[\\]]")


def _check_shell_meta(arg: str) -> None:
    """Raise SecurityError if `arg` contains any shell metacharacter."""
    if _SHELL_META_RE.search(arg):
        snippet = arg[:50] + "..." if len(arg) > 50 else arg
        raise SecurityError(f"Forbidden shell metacharacter in arg: {snippet}")


def safe_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """
    Hardened wrapper around subprocess.run.

    Args:
        cmd: Command and arguments as a list of strings.  Must NOT be a
             single string (shell-style concatenation is forbidden).
        **kwargs: Extra keyword arguments forwarded to subprocess.run.
                  ``shell=True`` is explicitly rejected.

    Returns:
        subprocess.CompletedProcess instance.

    Raises:
        SecurityError: If ``shell=True`` is passed, if ``cmd`` is not a
                       list, or if any argument contains shell metacharacters.
    """
    # 1. Reject shell=True unconditionally
    if kwargs.get("shell"):
        raise SecurityError("shell=True is forbidden")

    # 2. Enforce list-only commands
    if not isinstance(cmd, list):
        raise SecurityError("cmd must be a list[str]; string concatenation is forbidden")

    # 3. Validate every argument for shell metacharacters
    for arg in cmd:
        if not isinstance(arg, str):
            raise SecurityError(f"All cmd elements must be str, got {type(arg).__name__}")
        _check_shell_meta(arg)

    # 4. Force shell=False and run
    kwargs["shell"] = False
    return subprocess.run(cmd, **kwargs)
