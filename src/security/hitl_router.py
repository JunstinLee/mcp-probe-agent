"""Human-in-the-Loop (HITL) router for high-risk tool operations."""

from __future__ import annotations

import asyncio
import os
from enum import Enum

HIGH_RISK_TOOLS = {"write_file", "delete_file", "execute_shell", "send_email"}


class RiskLevel(Enum):
    LOW = "low"
    HIGH = "high"


def classify_risk(tool_name: str) -> RiskLevel:
    return RiskLevel.HIGH if tool_name in HIGH_RISK_TOOLS else RiskLevel.LOW


def require_human_approval(tool_name: str, arguments: dict) -> bool:
    if os.environ.get("MCP_HITL_AUTO_APPROVE") == "1":
        return False
    return classify_risk(tool_name) == RiskLevel.HIGH


async def prompt_for_approval(tool_name: str, arguments: dict) -> bool:
    print(f"\n[HITL] 高危操作请求: {tool_name}")
    print(f"[HITL] 参数: {arguments}")
    response = await asyncio.to_thread(
        input, "[HITL] 是否允许执行？输入 yes 确认，其他任意键拒绝: "
    )
    return response.strip().lower() == "yes"
