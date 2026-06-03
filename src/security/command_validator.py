"""
Command argument validator — whitelist-based parameter hardening.

For any tool argument that may eventually reach a shell or subprocess,
apply a strict character whitelist and length limits.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Whitelist & length limits
# ---------------------------------------------------------------------------

_MAX_ARG_LEN = 4096

# Allowed characters: alphanum, underscore, dot, slash, hyphen
_WHITELIST_RE = re.compile(r"^[A-Za-z0-9_./\-]+$")


def validate_command_arg(value: str) -> str:
    """
    Validate that ``value`` is safe to pass as a command-line argument.

    Checks:
        - Not empty or pure whitespace.
        - Length <= 4096 characters.
        - Contains only whitelisted characters.

    Args:
        value: The argument string to validate.

    Returns:
        The original string (for convenience in call chains).

    Raises:
        ValueError: If any check fails.
    """
    if not value or not value.strip():
        raise ValueError("argument is empty or whitespace")

    if len(value) > _MAX_ARG_LEN:
        raise ValueError(f"argument exceeds max length of {_MAX_ARG_LEN} characters")

    if not _WHITELIST_RE.match(value):
        raise ValueError(
            "argument contains forbidden characters; "
            "allowed: A-Z a-z 0-9 _ . / -"
        )

    return value
