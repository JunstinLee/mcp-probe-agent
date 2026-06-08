from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal


@dataclass
class GuardrailResult:
    safe: bool
    action: Literal["allow", "block", "mask"]
    reason: str


_TAG_ESCAPE_RE = re.compile(
    r"</EXTERNAL_CONTEXT>.*?(system\s+instruction|ignore|override|disregard)",
    re.DOTALL | re.IGNORECASE,
)

_SYSTEM_PROMPT_HIJACK_RE = re.compile(
    r"(you\s+are\s+now|act\s+as|pretend\s+you\s+are|your\s+new\s+role)",
    re.IGNORECASE,
)

_OOB_INSTRUCTION_RE = re.compile(
    r"(output\s+only|do\s+not\s+summarize|bypass|jailbreak)",
    re.IGNORECASE,
)


def _local_heuristic(text: str) -> GuardrailResult:
    """Fast local checks that do not require a model."""
    if _TAG_ESCAPE_RE.search(text):
        return GuardrailResult(safe=False, action="block", reason="tag breakout pattern detected")
    if _SYSTEM_PROMPT_HIJACK_RE.search(text):
        return GuardrailResult(safe=False, action="mask", reason="suspected prompt hijack pattern")
    if _OOB_INSTRUCTION_RE.search(text):
        return GuardrailResult(safe=False, action="mask", reason="suspected out-of-band instruction")
    return GuardrailResult(safe=True, action="allow", reason="local heuristic passed")


async def _remote_guardrail(text: str, context: str = "tool_output") -> GuardrailResult:
    """Call an external guardrail API endpoint (placeholder)."""
    endpoint = os.environ.get("MCP_GUARDRAIL_ENDPOINT", "")
    if not endpoint:
        return GuardrailResult(safe=False, action="block", reason="guardrail endpoint not configured")
    # In production, this would POST to the endpoint and parse the result.
    # For now, fall through to local heuristic.
    return _local_heuristic(text)


async def guardrail_check(
    text: str,
    context: str = "tool_output",
    mode: str | None = None,
) -> GuardrailResult:
    """
    Perform a semantic safety review on tool output text.

    Mode is determined by:
        - ``mode`` parameter (if provided)
        - ``MCP_GUARDRAIL_MODE`` environment variable (``off`` / ``local`` / ``remote``)
        - Defaults to ``local``

    Args:
        text: The tool output text to review.
        context: Label for the review context (e.g. ``tool_output``, ``scrape_webpage``).
        mode: Override guardrail mode. One of ``off``, ``local``, ``remote``.

    Returns:
        ``GuardrailResult`` with safe/action/reason.
    """
    effective_mode = mode or os.environ.get("MCP_GUARDRAIL_MODE", "local")

    if effective_mode == "off":
        return GuardrailResult(safe=True, action="allow", reason="guardrail disabled")

    if effective_mode == "remote":
        return await _remote_guardrail(text, context)

    return _local_heuristic(text)
