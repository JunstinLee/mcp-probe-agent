# MCP Security Probe — Attack Payloads

## Overview

This repository executes **24 automated attack payloads** against a secured MCP (Model Context Protocol) server to validate defense-in-depth measures. All payloads target the secure server (`probe_server_secure.py` on port 8766).

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

### 3. Path Traversal Bypass

| Payload | Target | Description |
|---------|--------|-------------|
| Unicode normalization bypass | `read_secure_file` | Uses fullwidth Unicode dots (`．．／`) to bypass ASCII-only path filters. |
| Double-write traversal bypass | `read_secure_file` | Interleaves legitimate paths with traversal (`hello.txt/../../etc/passwd`). |
| Case variation bypass | `read_secure_file` | Uses uppercase system paths (`../../ETC/PASSWD`) to exploit case-insensitive filesystems. |
| Symlink escape precondition | `read_secure_file` | Attempts to read a symlink inside the sandbox that points outside. |
| Long prefix traversal bypass | `read_secure_file` | Prefixes traversal with an extremely long path string to stress validation. |

### 4. Timing Injection

| Payload | Target | Description |
|---------|--------|-------------|
| Long path exhaustion | `read_secure_file` | Submits a 1000+ character path to trigger excessive CPU/IO processing. |
| Deep nesting traversal | `read_secure_file` | Submits a 100+ level nested directory path to stress path resolution. |

### 5. Resource Exhaustion / Denial of Service

| Payload | Target | Description |
|---------|--------|-------------|
| Large content write | `write_file` | Writes a 10 MB payload to exhaust disk space. |
| Symlink loop detection | `read_secure_file` | Attempts to read a circular symlink to trigger infinite resolution loops. |

### 6. Network Layer & Authentication

| Payload | Target | Description |
|---------|--------|-------------|
| Missing Bearer token on message endpoint | `read_secure_file` | Sends a request to `/message` without an `Authorization` header to test auth enforcement. |
| DNS Rebinding to loopback | `scrape_webpage` | Requests `http://localhost` to test DNS-level IP resolution blocking (rebinding protection). |
| Cross-tenant path traversal | `read_secure_file` | User `user_a` attempts to read `../user_b/secret.txt` to escape their own sandbox. |
| Cross-tenant write to another sandbox | `write_file` | User `user_a` attempts to write `../admin/backdoor.txt` to poison another tenant. |

### 7. Semantic Bypass

| Payload | Target | Description |
|---------|--------|-------------|
| Base64-encoded prompt injection | `scrape_webpage` | Base64-encoded adversarial instructions bypass plain-text regex filters until decoded by the LLM. |
| Unicode fullwidth injection bypass | `scrape_webpage` | Fullwidth Unicode characters evade ASCII-only regex filters while being interpreted by the LLM. |

### 8. Data Exfiltration

| Payload | Target | Description |
|---------|--------|-------------|
| Query secrets table for API key leak | `query_mock_db` | Directly querying the secrets table to leak API keys and passwords. |
| Read file containing embedded API key | `read_secure_file` | Reading arbitrary files that contain API keys or credentials. |
| Scraper output containing AWS credentials | `scrape_webpage` | Scraped web pages containing hardcoded AWS credentials that bypass input validation but leak through output. |


