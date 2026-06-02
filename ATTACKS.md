# MCP Security Probe — Attack Payloads

## Overview

This repository executes **11 automated attack payloads** against a secured MCP (Model Context Protocol) server to validate defense-in-depth measures. All payloads target the secure server (`probe_server_secure.py` on port 8766).

## Attack Categories

### 1. Server-Side Request Forgery (SSRF)

| Payload | Target | Description |
|---------|--------|-------------|
| Cloud metadata endpoint probe | `scrape_webpage` | Requests `http://169.254.169.254/latest/meta-data/` to steal cloud instance credentials. |
| Internal network scan | `scrape_webpage` | Requests `http://10.0.0.1/admin` to probe internal services. |

### 2. Path Traversal Bypass

| Payload | Target | Description |
|---------|--------|-------------|
| Unicode normalization bypass | `read_secure_file` | Uses fullwidth Unicode dots (`．．／`) to bypass ASCII-only path filters. |
| Double-write traversal bypass | `read_secure_file` | Interleaves legitimate paths with traversal (`hello.txt/../../etc/passwd`). |
| Case variation bypass | `read_secure_file` | Uses uppercase system paths (`../../ETC/PASSWD`) to exploit case-insensitive filesystems. |
| Long prefix traversal bypass | `read_secure_file` | Prefixes traversal with an extremely long path string. |

### 3. Symlink Escape

| Payload | Target | Description |
|---------|--------|-------------|
| Symlink loop detection | `read_secure_file` | Attempts to read a circular symlink to trigger infinite resolution. |
| Symlink escape precondition | `read_secure_file` | Attempts to read a symlink inside the sandbox that points outside. |

### 4. Resource Exhaustion / Denial of Service

| Payload | Target | Description |
|---------|--------|-------------|
| Large content write | `write_file` | Writes a 10 MB payload to exhaust disk space. |
| Long path exhaustion | `read_secure_file` | Submits a 1000+ character path to trigger CPU/IO overhead. |
| Deep nesting traversal | `read_secure_file` | Submits a 100+ level nested directory path to stress path resolution. |

## Test Results

All 11 payloads executed against the secure server. Result: **11/11 blocked**.

- **SSRF attacks**: Blocked by URL validation rejecting private IP ranges.
- **Path traversal attacks**: Blocked by canonical path resolution and sandbox containment.
- **Symlink attacks**: Blocked by explicit symlink rejection.
- **Resource exhaustion attacks**: Blocked by write-size limits and OS-level path length enforcement.
