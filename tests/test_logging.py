"""Tests for logger redaction default policy and log rotation.

Validates that sensitive data is redacted by default and can be disabled
via MCP_LOG_NO_REDACT=1.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from src.logger import _capture_buffer, _redact_sensitive, get_captured_packets, log_packet, reset_run_dir


class TestRedactSensitive:
    def test_api_key_redacted(self):
        payload = {"api_key": "sk-secret-123"}
        result = _redact_sensitive(payload)
        assert result["api_key"] == "[REDACTED]"

    def test_password_redacted(self):
        payload = {"db_password": "hunter2"}
        result = _redact_sensitive(payload)
        assert result["db_password"] == "[REDACTED]"

    def test_secret_redacted(self):
        payload = {"client_secret": "abc123xyz"}
        result = _redact_sensitive(payload)
        assert result["client_secret"] == "[REDACTED]"

    def test_token_redacted(self):
        payload = {"access_token": "bearer-token-data"}
        result = _redact_sensitive(payload)
        assert result["access_token"] == "[REDACTED]"

    def test_nested_sensitive_redacted(self):
        payload = {"auth": {"api_key": "nested-secret"}}
        result = _redact_sensitive(payload)
        assert result["auth"]["api_key"] == "[REDACTED]"

    def test_non_sensitive_preserved(self):
        payload = {"username": "alice", "table": "users"}
        result = _redact_sensitive(payload)
        assert result["username"] == "alice"
        assert result["table"] == "users"

    def test_list_of_dicts_redacted(self):
        payload = {"items": [{"password": "p1"}, {"password": "p2"}]}
        result = _redact_sensitive(payload)
        assert result["items"][0]["password"] == "[REDACTED]"
        assert result["items"][1]["password"] == "[REDACTED]"


class TestDefaultRedaction:
    """Verify that redaction is ON by default (MCP_LOG_NO_REDACT=1 disables it)."""

    def setup_method(self):
        from src.logger import _capture_buffer
        _capture_buffer.clear()
        reset_run_dir()
        os.environ.pop("MCP_LOG_NO_REDACT", None)

    def teardown_method(self):
        reset_run_dir()
        os.environ.pop("MCP_LOG_NO_REDACT", None)

    def test_default_redaction_on(self):
        log_packet("inbound", {"api_key": "sk-super-secret-1234567890"})
        packets = get_captured_packets()
        assert len(packets) == 1
        entry_str = str(packets[0])
        assert "sk-super-secret-1234567890" not in entry_str
        assert "[REDACTED]" in entry_str

    def test_redaction_off_with_env(self):
        from src.logger import _capture_buffer
        _capture_buffer.clear()
        os.environ["MCP_LOG_NO_REDACT"] = "1"
        reset_run_dir()
        log_packet("inbound", {"api_key": "sk-raw-secret-data"})
        packets = get_captured_packets()
        assert len(packets) == 1
        entry_str = str(packets[0])
        assert "sk-raw-secret-data" in entry_str
