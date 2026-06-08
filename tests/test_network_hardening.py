"""Tests for network layer hardening: Nginx config and Uvicorn parameters."""

from __future__ import annotations

from pathlib import Path


class TestNginxConfig:
    def test_config_file_exists(self):
        config = Path("deploy/nginx.conf")
        assert config.exists(), "deploy/nginx.conf should exist"

    def test_config_has_rate_limiting(self):
        config = Path("deploy/nginx.conf")
        content = config.read_text()
        assert "limit_req_zone" in content
        assert "limit_conn_zone" in content

    def test_config_has_sse_proxy(self):
        config = Path("deploy/nginx.conf")
        content = config.read_text()
        assert "/sse" in content
        assert "proxy_pass" in content
        assert "proxy_buffering off" in content

    def test_config_has_message_endpoint(self):
        config = Path("deploy/nginx.conf")
        content = config.read_text()
        assert "/message" in content
        assert "limit_req" in content
        assert "limit_conn" in content

    def test_config_has_health_check(self):
        config = Path("deploy/nginx.conf")
        content = config.read_text()
        assert "/health" in content

    def test_config_has_upstream_block(self):
        config = Path("deploy/nginx.conf")
        content = config.read_text()
        assert "upstream mcp_secure" in content or "upstream mcp_secure_backend" in content
        assert "127.0.0.1:8766" in content


class TestUvicornHardening:
    def test_server_code_has_timeout_keep_alive(self):
        server_file = Path("src/probe_server_secure.py")
        content = server_file.read_text()
        assert "timeout_keep_alive" in content, "Uvicorn timeout_keep_alive should be set"

    def test_server_code_has_limit_max_requests(self):
        server_file = Path("src/probe_server_secure.py")
        content = server_file.read_text()
        assert "limit_max_requests" in content, "Uvicorn limit_max_requests should be set"
