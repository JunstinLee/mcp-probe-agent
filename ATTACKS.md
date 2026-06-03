# MCP Security Probe — Attack Payloads

## Overview

This repository executes **19 automated attack payloads** against a secured MCP (Model Context Protocol) server to validate defense-in-depth measures. All payloads target the secure server (`probe_server_secure.py` on port 8766).

## Attack Categories

### 1. Server-Side Request Forgery (SSRF)

| Payload | Target | Description |
|---------|--------|-------------|
| Cloud metadata endpoint probe | `scrape_webpage` | Requests `http://169.254.169.254/latest/meta-data/` to steal cloud instance credentials. |
| Internal network scan | `scrape_webpage` | Requests `http://10.0.0.1/admin` to probe internal services. |

### 2. Command Injection

| Payload | Target | Description |
|---------|--------|-------------|
| Semicolon command chaining | `read_secure_file` | Injects `; rm -rf /` via path argument to trigger shell command execution. |
| Backtick command substitution | `read_secure_file` | Injects backtick command substitution (`hello.txt`whoami``) via path argument. |
| Pipe to shell | `read_secure_file` | Uses pipe metacharacter (`hello.txt \| /bin/sh`) to chain arbitrary shell execution. |
| Ampersand background execution | `write_file` | Uses ampersand (`hello.txt & nc ...`) to fork a background reverse shell. |

### 3. Path Traversal & Bypass

| Payload | Target | Description |
|---------|--------|-------------|
| Unicode normalization bypass | `read_secure_file` | Uses fullwidth Unicode dots (`．．／`) to bypass ASCII-only path filters. |
| Double-write traversal bypass | `read_secure_file` | Interleaves legitimate paths with traversal (`hello.txt/../../etc/passwd`). |
| Case variation bypass | `read_secure_file` | Uses uppercase system paths (`../../ETC/PASSWD`) to exploit case-insensitive filesystems. |
| Long prefix traversal bypass | `read_secure_file` | Prefixes traversal with an extremely long path string to stress validation. |

### 4. Symlink Escape

| Payload | Target | Description |
|---------|--------|-------------|
| Symlink loop detection | `read_secure_file` | Attempts to read a circular symlink to trigger infinite resolution. |
| Symlink escape precondition | `read_secure_file` | Attempts to read a symlink inside the sandbox that points outside. |

### 5. Resource Exhaustion / Denial of Service

| Payload | Target | Description |
|---------|--------|-------------|
| Large content write | `write_file` | Writes a 10 MB payload to exhaust disk space. |
| Long path exhaustion | `read_secure_file` | Submits a 1000+ character path to trigger CPU/IO overhead. |
| Deep nesting traversal | `read_secure_file` | Submits a 100+ level nested directory path to stress path resolution. |

### 6. Network Layer & Authentication

| Payload | Target | Description |
|---------|--------|-------------|
| Missing Bearer token on message endpoint | `read_secure_file` | Sends a request to `/message` without an `Authorization` header to test auth enforcement. |
| DNS Rebinding to loopback | `scrape_webpage` | Requests `http://localhost` to test DNS-level IP resolution blocking (rebinding protection). |

### 7. Multi-Tenant Isolation

| Payload | Target | Description |
|---------|--------|-------------|
| Cross-tenant path traversal | `read_secure_file` | User `user_a` attempts to read `../user_b/secret.txt` to escape their own sandbox. |
| Cross-tenant write to another sandbox | `write_file` | User `user_a` attempts to write `../admin/backdoor.txt` to poison another tenant. |

## Test Results

All **19 payloads** executed against the secure server. Result: **19/19 blocked**.

- **SSRF attacks**: Blocked by URL validation rejecting private IP ranges at both string-level and DNS-resolved IP level.
- **Command injection attacks**: Blocked by shell metacharacter rejection in all path and filename arguments.
- **Path traversal attacks**: Blocked by canonical path resolution (`Path.resolve()`) and sandbox containment (`is_relative_to()`).
- **Symlink attacks**: Blocked by explicit `os.path.islink()` rejection before filesystem access.
- **Resource exhaustion attacks**: Blocked by write-size limits (`MAX_WRITE_SIZE = 1 MB`) and OS-level path length enforcement.
- **Authentication bypass**: Blocked by `BearerAuthMiddleware` enforcing token validation on `/message` and `/sse` endpoints.
- **DNS rebinding**: Blocked by `socket.getaddrinfo()` DNS resolution followed by IP-level blacklist validation.
- **Multi-tenant escape**: Blocked by per-user sandbox containment with prefix locking via `is_relative_to()`.
