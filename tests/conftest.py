"""Pytest configuration and shared fixtures."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def sandbox_dir(tmp_path: pytest.fixture) -> Path:
    """Create a temporary sandbox directory with a seed file."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    hello_file = sandbox / "hello.txt"
    hello_file.write_text("Hello, World!")
    return sandbox


@pytest.fixture
def mock_server_args() -> dict:
    """Return a dict with standard tool call parameters."""
    return {
        "tool_name": "read_secure_file",
        "arguments": {"path": "legitimate/path.txt"},
        "request_id": "test-request-001",
    }


@pytest.fixture
def traversal_payloads() -> list[dict]:
    """Load and return path_traversal entries from payloads.json."""
    payloads_path = Path(__file__).parent.parent / "exploits" / "payloads.json"
    with open(payloads_path) as f:
        all_payloads = json.load(f)
    return [p for p in all_payloads if p.get("category") == "path_traversal"]