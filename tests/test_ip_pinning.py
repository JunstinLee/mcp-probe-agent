"""Tests for validate_url() ResolvedUrl return type and DNS rebinding defense."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from src.validators import ResolvedUrl, validate_url


class TestResolvedUrl:
    def test_resolved_url_creation(self):
        ru = ResolvedUrl(
            original_url="http://example.com/path",
            resolved_ip="93.184.216.34",
            hostname="example.com",
            port=80,
            scheme="http",
        )
        assert ru.hostname == "example.com"
        assert ru.resolved_ip == "93.184.216.34"
        assert ru.port == 80
        assert ru.scheme == "http"
        assert ru.original_url == "http://example.com/path"

    def test_resolved_url_equality(self):
        a = ResolvedUrl("http://x.com", "1.1.1.1", "x.com", 80, "http")
        b = ResolvedUrl("http://x.com", "1.1.1.1", "x.com", 80, "http")
        assert a == b

    def test_resolved_url_https_default_port(self):
        ru = ResolvedUrl("https://sec.com", "1.2.3.4", "sec.com", 443, "https")
        assert ru.port == 443

    def test_resolved_url_repr(self):
        ru = ResolvedUrl("http://a.com", "1.1.1.1", "a.com", 80, "http")
        r = repr(ru)
        assert "a.com" in r
        assert "1.1.1.1" in r


class TestValidateUrl:
    def test_public_host_returns_resolved_url(self):
        result = validate_url("http://example.com")
        assert isinstance(result, ResolvedUrl)
        assert result.hostname == "example.com"
        assert result.resolved_ip != ""
        assert result.scheme == "http"
        assert result.port == 80

    def test_https_default_port(self):
        result = validate_url("https://example.com")
        assert result.scheme == "https"
        assert result.port == 443

    def test_explicit_port(self):
        result = validate_url("http://example.com:8080/path")
        assert result.port == 8080

    def test_localhost_blocked_by_hostname(self):
        with pytest.raises(ValueError, match="internal address"):
            validate_url("http://127.0.0.1/admin")

    def test_private_ip_blocked_by_hostname(self):
        with pytest.raises(ValueError, match="internal address"):
            validate_url("http://10.0.0.1/admin")

    def test_metadata_endpoint_blocked(self):
        with pytest.raises(ValueError, match="internal address"):
            validate_url("http://169.254.169.254/latest/meta-data/")

    def test_invalid_url_format_raises(self):
        """URLs with unparseable hosts should raise."""
        with pytest.raises(ValueError):
            validate_url("not-a-valid-url")

    def test_dns_rebinding_defense(self):
        """Simulate DNS rebinding: hostname passes string check but resolves to loopback."""
        with patch.object(socket, "getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]
            with pytest.raises(ValueError, match="internal address"):
                validate_url("http://evil-rebind.example.com")
