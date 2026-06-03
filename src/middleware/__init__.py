"""Middleware package for MCP probe agent."""

from src.middleware.auth import BearerAuthMiddleware

__all__ = ["BearerAuthMiddleware"]
