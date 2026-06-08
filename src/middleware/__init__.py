"""Middleware package for MCP probe agent."""

from src.middleware.auth import BearerAuthMiddleware
from src.middleware.dlp_scanner import ScanHook, default_scan_hook, scan_text
from src.middleware.guardrail import GuardrailResult, guardrail_check
from src.middleware.hitl_router import (
    HIGH_RISK_TOOLS,
    RiskLevel,
    classify_risk,
    prompt_for_approval,
    require_human_approval,
)
from src.middleware.token_budget import SessionBudget

__all__ = [
    "BearerAuthMiddleware",
    "GuardrailResult",
    "SessionBudget",
    "ScanHook",
    "RiskLevel",
    "HIGH_RISK_TOOLS",
    "classify_risk",
    "default_scan_hook",
    "guardrail_check",
    "prompt_for_approval",
    "require_human_approval",
    "scan_text",
]
