"""Bearer Token authentication middleware for MCP SSE server."""

from __future__ import annotations

import os
from typing import Any

from starlette.responses import JSONResponse


class BearerAuthMiddleware:
    """ASGI middleware that enforces Bearer token auth on /message and /sse."""

    def __init__(self, app: Any, api_key: str | None = None):
        self.app = app
        self.disable = os.environ.get("MCP_AUTH_DISABLE") == "1"
        self.api_key = api_key or os.environ.get("MCP_API_KEY", "test-api-key")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        if self.disable:
            return await self.app(scope, receive, send)

        if scope.get("type") == "http" and scope.get("path") in ("/message", "/sse"):
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("latin-1")
            if not auth_header.startswith("Bearer ") or auth_header[7:] != self.api_key:
                response = JSONResponse(
                    {"error": "Unauthorized: invalid or missing Bearer token"},
                    status_code=401,
                )
                return await response(scope, receive, send)

        return await self.app(scope, receive, send)
