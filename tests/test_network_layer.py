"""
Tests for network and session layer security:
- Bearer token authentication on SSE endpoints
- DNS Rebinding protection in validate_url
"""

from __future__ import annotations

import os
import socket
from unittest.mock import patch

import pytest

from src.middleware.auth import BearerAuthMiddleware
from src.validators import validate_url


# ---------------------------------------------------------------------------
# BearerAuthMiddleware tests
# ---------------------------------------------------------------------------

class TestBearerAuthMiddleware:
    """Unit tests for the Bearer token auth middleware."""

    @pytest.fixture
    def dummy_app(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"ok": true}'})
        return app

    @pytest.fixture
    def mock_request(self):
        from starlette.requests import Request
        scope = {
            "type": "http",
            "path": "/message",
            "headers": [(b"authorization", b"Bearer test-api-key")],
            "method": "POST",
            "scheme": "http",
            "server": ("127.0.0.1", 8766),
            "client": ("127.0.0.1", 50000),
            "root_path": "",
            "query_string": b"",
        }
        async def _receive():
            return {"type": "http.request"}
        return Request(scope, receive=_receive)

    async def test_valid_token_passes(self, dummy_app, mock_request):
        middleware = BearerAuthMiddleware(dummy_app)

        async def call_next(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"ok": True})

        response = await middleware.dispatch(mock_request, call_next)
        assert response.status_code == 200

    async def test_missing_token_returns_401(self, dummy_app):
        from starlette.requests import Request
        scope = {"type": "http", "path": "/message", "headers": [], "method": "POST", "scheme": "http", "server": ("127.0.0.1", 8766), "client": ("127.0.0.1", 50000), "root_path": "", "query_string": b""}
        async def _receive():
            return {"type": "http.request"}
        request = Request(scope, receive=_receive)
        middleware = BearerAuthMiddleware(dummy_app)

        async def call_next(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"ok": True})

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

    async def test_wrong_token_returns_401(self, dummy_app):
        from starlette.requests import Request
        scope = {"type": "http", "path": "/message", "headers": [(b"authorization", b"Bearer wrong-token")], "method": "POST", "scheme": "http", "server": ("127.0.0.1", 8766), "client": ("127.0.0.1", 50000), "root_path": "", "query_string": b""}
        async def _receive():
            return {"type": "http.request"}
        request = Request(scope, receive=_receive)
        middleware = BearerAuthMiddleware(dummy_app)

        async def call_next(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"ok": True})

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401

    async def test_disabled_auth_allows_all(self, dummy_app):
        from starlette.requests import Request
        scope = {"type": "http", "path": "/message", "headers": [], "method": "POST", "scheme": "http", "server": ("127.0.0.1", 8766), "client": ("127.0.0.1", 50000), "root_path": "", "query_string": b""}
        async def _receive():
            return {"type": "http.request"}
        request = Request(scope, receive=_receive)
        with patch.dict(os.environ, {"MCP_AUTH_DISABLE": "1"}):
            middleware = BearerAuthMiddleware(dummy_app)

            async def call_next(request):
                from starlette.responses import JSONResponse
                return JSONResponse({"ok": True})

            response = await middleware.dispatch(request, call_next)
            assert response.status_code == 200

    async def test_sse_endpoint_also_protected(self, dummy_app):
        from starlette.requests import Request
        scope = {"type": "http", "path": "/sse", "headers": [], "method": "GET", "scheme": "http", "server": ("127.0.0.1", 8766), "client": ("127.0.0.1", 50000), "root_path": "", "query_string": b""}
        async def _receive():
            return {"type": "http.request"}
        request = Request(scope, receive=_receive)
        middleware = BearerAuthMiddleware(dummy_app)

        async def call_next(request):
            from starlette.responses import JSONResponse
            return JSONResponse({"ok": True})

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# DNS Rebinding protection tests
# ---------------------------------------------------------------------------

class TestValidateUrlDnsRebinding:
    """Tests for the socket-level DNS rebinding defense in validate_url."""

    def test_public_url_allowed(self):
        # google.com should resolve to public IPs and be allowed
        validate_url("https://google.com")

    def test_private_ip_blocked_at_string_level(self):
        with pytest.raises(ValueError, match="access to internal address"):
            validate_url("http://127.0.0.1/admin")

    def test_private_ip_blocked_at_socket_level(self):
        # Simulate a DNS rebinding scenario where evil.example.com resolves to 127.0.0.1
        with patch.object(
            socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))
            ],
        ):
            with pytest.raises(ValueError, match="DNS resolved to internal address"):
                validate_url("http://evil.example.com")

    def test_dns_rebinding_to_10_range_blocked(self):
        with patch.object(
            socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
            ],
        ):
            with pytest.raises(ValueError, match="DNS resolved to internal address"):
                validate_url("http://internal-target.example.com")

    def test_unresolvable_host_blocked(self):
        with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror):
            with pytest.raises(ValueError, match="cannot resolve host"):
                validate_url("http://does-not-exist-12345.local")

    def test_public_dns_resolution_allowed(self):
        # Simulate a public IP resolution
        with patch.object(
            socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("142.250.80.46", 0))
            ],
        ):
            validate_url("http://example.com")

    def test_cloud_metadata_blocked_at_socket_level(self):
        with patch.object(
            socket,
            "getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))
            ],
        ):
            with pytest.raises(ValueError, match="DNS resolved to internal address"):
                validate_url("http://metadata.example.com")
