"""Tests for the DLP (Data Loss Prevention) scanner."""

from __future__ import annotations

import pytest

from src.security.dlp_scanner import scan_text, default_scan_hook


class TestScanText:
    """Tests for scan_text core function."""

    def test_no_sensitive_data(self):
        text = "This is a completely innocent paragraph about cats and dogs."
        masked, detected = scan_text(text)
        assert masked == text
        assert detected == []

    def test_api_key_generic(self):
        text = "The API key is sk-mock-123456789 for testing."
        masked, detected = scan_text(text)
        assert "API_KEY_GENERIC" in detected
        assert "[REDACTED-API_KEY_GENERIC]" in masked
        assert "sk-mock-123456789" not in masked

    def test_aws_access_key(self):
        text = "AKIAIOSFODNN7EXAMPLE is an AWS access key."
        masked, detected = scan_text(text)
        assert "AWS_ACCESS_KEY" in detected
        assert "[REDACTED-AWS_ACCESS_KEY]" in masked
        assert "AKIAIOSFODNN7EXAMPLE" not in masked

    def test_ssn(self):
        text = "Patient SSN: 123-45-6789"
        masked, detected = scan_text(text)
        assert "SSN" in detected
        assert "[REDACTED-SSN]" in masked
        assert "123-45-6789" not in masked

    def test_email(self):
        text = "Contact us at admin@example.com for details."
        masked, detected = scan_text(text)
        assert "EMAIL" in detected
        assert "[REDACTED-EMAIL]" in masked
        assert "admin@example.com" not in masked

    def test_credit_card(self):
        text = "Card number: 4111111111111111"
        masked, detected = scan_text(text)
        assert "CREDIT_CARD" in detected
        assert "[REDACTED-CREDIT_CARD]" in masked
        assert "4111111111111111" not in masked

    def test_multiple_patterns(self):
        text = "Key: sk-abc1234567890123456789, Email: user@test.com"
        masked, detected = scan_text(text)
        assert "API_KEY_GENERIC" in detected
        assert "EMAIL" in detected
        assert "[REDACTED-API_KEY_GENERIC]" in masked
        assert "[REDACTED-EMAIL]" in masked

    def test_china_id(self):
        text = "ID: 110101199001011234"
        masked, detected = scan_text(text)
        assert "CHINA_ID" in detected
        assert "[REDACTED-CHINA_ID]" in masked
        assert "110101199001011234" not in masked

    def test_mock_db_secret(self):
        """The exact mock secret from probe_server_secure.py MOCK_DB."""
        text = "api_key: sk-mock-123456789"
        masked, detected = scan_text(text)
        assert "API_KEY_GENERIC" in detected
        assert "[REDACTED-API_KEY_GENERIC]" in masked


class TestDefaultScanHook:
    """Tests for the default scan hook compatibility."""

    def test_returns_tuple(self):
        text = "sk-test-key-12345678901234567890"
        result = default_scan_hook(text)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[1], list)
