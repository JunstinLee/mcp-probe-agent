# MCP Security Probe — Defense Mechanisms

## Overview

This document describes the defense mechanisms implemented in `probe_server_secure.py` and supporting modules. All controls are applied to the secure MCP server running on port 8766.

---

## 1. Path Sandboxing

**File**: `src/validators.py` — `validate_sandbox_path()`

Every filesystem operation validates the requested path through a 7-step pipeline:

1. **Shell metacharacter rejection** — Rejects any path containing characters from the blacklist `;|&$`\n<>{}[]`.
2. **Null byte rejection** — Rejects paths containing `\0` to prevent C-style string truncation attacks.
3. **Canonical base resolution** — Resolves the per-user sandbox directory once via `Path.resolve()`.
4. **Target path resolution** — Joins the requested path with the sandbox base and resolves again.
5. **Prefix containment check** — Ensures the resolved target is strictly inside the sandbox using `Path.is_relative_to()`.
6. **Symlink rejection** — Explicitly rejects symbolic links via `os.path.islink()` before any read/write.
7. **Resolved Path return** — Returns the canonical `Path` object for the caller to use.

**Per-user sandbox**: Each `user_id` receives an isolated subdirectory under `/tmp/mcp_sandbox_secure/{user_id}`. Cross-tenant traversal is impossible because step 5 locks the path to the caller's own sandbox prefix.

---

## 2. SSRF / URL Validation

**File**: `src/validators.py` — `validate_url()`

Two-layer validation prevents Server-Side Request Forgery:

- **String-level block** — Hostnames matching private IP prefixes are rejected immediately:
  - `0.0.0.0`, `127.*`, `10.*`, `172.16-31.*`, `192.168.*`, `169.254.*`
- **DNS resolution block** — The hostname is resolved via `socket.getaddrinfo()`. If any resolved IP falls into the private ranges above, the request is rejected. This closes DNS rebinding attacks where a public hostname resolves to a loopback or internal IP at socket time.

---

## 3. Command Injection Prevention

Three independent layers block shell metacharacter injection:

### Layer A — Path-level blacklist
**File**: `src/validators.py`

`_SHELL_METACHARS = frozenset(";|&$`\n<>{}[]")`

Any path or filename argument containing these characters is rejected before reaching the filesystem.

### Layer B — Subprocess hardening
**File**: `src/security/subprocess_guard.py`

- `shell=True` is unconditionally forbidden.
- Commands must be passed as `list[str]`; string concatenation is rejected.
- Every list element is checked against the regex `[;|&$`\n<>{}\[\]]`.

### Layer C — Argument whitelist
**File**: `src/security/command_validator.py`

Arguments must match `^[A-Za-z0-9_./\-]+$` and cannot exceed 4096 characters.

---

## 4. Prompt Injection & Output Sanitization

**File**: `src/validators.py` — `sanitize_output()`

Tool outputs are sanitized through a 4-stage pipeline before reaching the LLM context:

1. **Unicode normalization** — Applies `unicodedata.normalize("NFKC", text)` to collapse fullwidth and compatibility characters (e.g. `Ｉｇｎｏｒｅ` → `Ignore`).
2. **Base64 decoding** — Scans for Base64 segments (`[A-Za-z0-9+/]{40,}={0,2}`), decodes them, and checks the plaintext for injection patterns. Encoded payloads are replaced with `[FILTERED-B64]`.
3. **Injection pattern detection** — Matches English trigger phrases via regex:
   `(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|before)\s+(instructions?|directives?|prompts?)`
   Hits are replaced with `[FILTERED]`.
4. **Delimiter breakout detection** — Matches `` `\`\`\`system...`\`\`\` `` patterns and replaces them with `[FILTERED-DELIMITER]`.

**Output wrapper**: Sanitized content is wrapped in `<EXTERNAL_CONTEXT>` tags with an explicit warning that the content is untrusted and must never be interpreted as system instructions.

---

## 5. Resource Exhaustion Limits

### Write size cap
**File**: `src/probe_server_secure.py`

`MAX_WRITE_SIZE = 1024 * 1024` (1 MB). Any `write_file` call exceeding this limit raises `ToolError` immediately.

### Session circuit breaker
**File**: `src/security/token_budget.py`

`SessionBudget` enforces hard limits per orchestrator session:
- `MAX_TURNS = 20`
- `MAX_ESTIMATED_TOKENS = 20_000`

If either limit is exceeded, the orchestrator aborts with `RuntimeError`.

---

## 6. Authentication

**File**: `src/middleware/auth.py` — `BearerAuthMiddleware`

- All HTTP requests to `/message` and `/sse` require a valid `Authorization: Bearer <token>` header.
- The expected token defaults to `test-api-key` (overridable via `MCP_API_KEY` env var).
- Authentication can be disabled entirely by setting `MCP_AUTH_DISABLE=1`.

---

## 7. Multi-Tenant Isolation

**File**: `src/probe_server_secure.py`

The server computes a per-user sandbox path via `_get_user_sandbox(user_id)`. Every read and write operation validates the resolved path against this prefix. Because `validate_sandbox_path()` uses `is_relative_to()`, a user cannot escape their own directory to access another tenant's files, regardless of how many `../` segments are used.

---

## 8. Data Loss Prevention (DLP)

**File**: `src/security/dlp_scanner.py`

All tool outputs (`read_secure_file`, `query_mock_db`, `scrape_webpage`) and telemetry reports are scanned for sensitive patterns:

| Pattern | Regex |
|---------|-------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `[0-9a-zA-Z/+]{40}` |
| Generic API Key | `sk-[a-zA-Z0-9]{20,}` |
| China ID | `\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]` |
| SSN | `\d{3}-\d{2}-\d{4}` |
| Email | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` |
| Credit Card | `\b(?:4[0-9]{12}(?:[0-9]{3})?\|5[1-5][0-9]{14}\|3[47][0-9]{13})\b` |

Matches are replaced with `[REDACTED-{label}]` in the output. When detected, a `dlp_alert` telemetry packet is logged.

---

## 9. Human-in-the-Loop (HITL)

**File**: `src/security/hitl_router.py`

High-risk tools are classified as `RiskLevel.HIGH`:
- `write_file`
- `delete_file`
- `execute_shell`
- `send_email`

Before executing a high-risk tool, the server prints an interactive prompt requesting human confirmation (`yes` to allow, anything else to reject). This can be bypassed for automated testing by setting `MCP_HITL_AUTO_APPROVE=1`.

---

## 10. Input Argument Validation

**File**: `src/validators.py` — `validate_required_args()`

Tool arguments are validated structurally:
- **Unknown key rejection** — Any key not in the `allowed` set raises `ValueError`.
- **Required key enforcement** — All keys in `required` must be present and non-empty.
- **FastMCP strict mode** — `probe_server_secure.py` initializes the server with `strict_input_validation=True`, which rejects extra arguments at the framework level.

---

## 11. Process Isolation (Optional)

**File**: `src/security/sandbox_driver.py`

A lightweight sandbox driver can launch the server inside a Linux namespace:

```bash
unshare --net --pid --fork --mount-proc python src/probe_server_secure.py
```

- `--net` removes network access.
- `--pid` isolates the process tree.
- `--mount-proc` remounts procfs inside the namespace.

This is used by the shell scripts in `scripts/` and is controlled via the `network` flag.

---

## 12. Telemetry Log Redaction

**File**: `src/logger.py`

Telemetry packets are recursively scanned for sensitive field names matching:
- `api_key` / `api-key`
- `password`
- `secret`
- `token`

Values for these keys are replaced with `[REDACTED]` before writing to disk. Log files are rotated at 10 MB with up to 3 backups.
