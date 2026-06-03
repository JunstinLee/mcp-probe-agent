import re
from typing import Callable

# 敏感模式定义
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS_SECRET_KEY", re.compile(r'[0-9a-zA-Z/+]{40}')),  # 需结合上下文降低误报
    ("API_KEY_GENERIC", re.compile(r'sk-[a-zA-Z0-9]{20,}')),
    ("CHINA_ID", re.compile(r'\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]')),
    ("SSN", re.compile(r'\d{3}-\d{2}-\d{4}')),
    ("EMAIL", re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')),
    ("CREDIT_CARD", re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')),
]


def scan_text(text: str) -> tuple[str, list[str]]:
    """
    扫描文本中的敏感信息。
    返回: (脱敏后的文本, 检测到的敏感类型列表)
    """
    detected: list[str] = []
    masked = text
    for label, pattern in _PATTERNS:
        if pattern.search(masked):
            detected.append(label)
            masked = pattern.sub(f"[REDACTED-{label}]", masked)
    return masked, detected


# 扫描器挂载点
ScanHook = Callable[[str], tuple[str, list[str]]]


def default_scan_hook(text: str) -> tuple[str, list[str]]:
    return scan_text(text)
