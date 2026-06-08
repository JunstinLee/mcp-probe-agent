# mcp-probe-agent

A lightweight, Python-based probe environment and security sandbox designed to dissect Anthropic's Model Context Protocol (MCP), inspect raw JSON telemetry, and audit exploit vectors before full-scale Agent framework secondary development.

Companion docs: [ATTACKS.md](./ATTACKS.md) (24 payload catalog) · [PROTECT.md](./PROTECT.md) (defense detail)

---

## ⚡ Why This Repository Exists (The Strategic TL;DR)

While the Model Context Protocol (MCP) can sometimes feel like an over-engineered hype-train, it has undeniably become the gravitational well for open-source LLM tools and data sources. To build a highly compatible, next-generation Agent framework, you simply cannot bypass it.

However, trusting third-party protocol abstractions blindly is a recipe for architectural disaster. This repository serves as a **zero-overhead telemetry sandbox** to achieve three tactical goals:

1. **Unmask the Protocol:** Use a bare-minimum Python implementation to strip away the fluff and expose the raw JSON-RPC 2.0 payloads.
2. **Telemetry Inspection:** See *exactly* what data structures, schemas, and metadata are flying over the wire when an LLM requests a tool or resource.
3. **Security Defusal:** Map out critical threat vectors (Indirect Prompt Injection, Path Traversal) and establish framework-level defense blueprints before writing a single line of production framework code.

---

## 🏗️ Architecture & Component Layout

This sandbox bypasses complex wrappers, using the official `mcp` Python SDK to intercept and log every single network packet into a readable telemetry stream.

```
mcp-probe-agent/
├── main.py                          # Unified CLI entrypoint (run | attack | test | clean)
├── src/
│   ├── probe_server_secure.py       # Secure MCP Server (port 8766) — FastMCP + 4 tools
│   ├── inspector_client.py          # Attack orchestrator — 24 automated payloads
│   ├── logger.py                    # JSON packet capture, redaction, log rotation
│   ├── validators.py                # Path sandbox, URL/DNS validation, output sanitization
│   ├── cli/
│   │   ├── commands.py              # Subcommand implementations (run/attack/test/clean)
│   │   └── __init__.py
│   ├── middleware/
│   │   ├── auth.py                  # Bearer token ASGI middleware (SSE + message endpoints)
│   │   └── __init__.py
│   └── security/
│       ├── guardrail.py             # Semantic safety review (local heuristic + remote endpoint)
│       ├── dlp_scanner.py           # Data Loss Prevention — 7 regex patterns + redaction
│       ├── hitl_router.py           # Human-in-the-Loop gating for high-risk tools
│       ├── token_budget.py          # Session circuit breaker (max turns + token budget)
│       ├── subprocess_guard.py      # Subprocess hardening — no shell=True
│       ├── command_validator.py     # Argument whitelist validation
│       ├── sandbox_driver.py        # Linux namespace isolation (unshare)
│       └── __init__.py
├── tests/
│   ├── test_path_traversal.py       # Path sandbox escape & symlink tests
│   ├── test_prompt_injection.py     # Prompt injection & output sanitization
│   ├── test_semantic_defense.py     # Semantic bypass & guardrail tests
│   ├── test_input_validation.py     # URL/SSRF & argument validation
│   ├── test_command_injection.py    # Shell metacharacter injection
│   ├── test_argument_injection.py   # Argument tampering & unknown key rejection
│   ├── test_dlp.py                  # DLP redaction of secrets in outputs
│   ├── test_guardrail.py            # Guardrail blocking & masking behavior
│   ├── test_ip_pinning.py           # DNS rebinding & IP-pinned requests
│   ├── test_multitenant.py          # Cross-tenant sandbox isolation
│   ├── test_network_layer.py        # Auth & endpoint protection
│   ├── test_network_hardening.py    # Rate limiting & connection DoS
│   ├── test_sandbox.py              # Sandbox lifecycle & namespace isolation
│   ├── test_logging.py              # Telemetry redaction & log rotation
│   ├── test_integration.py          # End-to-end server + client flow
│   ├── test_smoke.py                # Server startup & basic health
│   ├── conftest.py                  # Shared fixtures
│   └── __init__.py
├── exploits/
│   └── payloads.json                # 24 automated attack payloads (8 categories)
├── deploy/
│   └── nginx.conf                   # Nginx reverse proxy with TLS + rate limiting
├── scripts/
│   ├── init_sandbox.sh              # Sandbox initialization
│   └── run_sandbox.sh               # Launch server in Linux namespace
├── .sisyphus/plans/                 # Security hardening roadmaps
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## 🚀 Quick Start

### 1. Environment Setup
```bash
# Clone the repository
git clone https://github.com/your-username/mcp-probe-agent.git
cd mcp-probe-agent

# Install dependencies
pip install -r requirements.txt
# or
uv sync
```

### 2. Run via CLI

A unified CLI entrypoint is provided at `main.py`:

```bash
# Terminal 1 — Start the secure server (port 8766)
python main.py run

# Terminal 2 — Run the attack orchestrator
python main.py attack

# Run the full pytest suite
python main.py test

# Clean sandbox / log files
python main.py clean
```

### 3. Launch Manually (Telemetry Mode)

Open two terminal windows to witness the raw JSON-RPC communication:

**Terminal 1 — Start the secure server**

```bash
python src/probe_server_secure.py
# Exposes:
#   GET  /sse     — SSE event stream (Bearer auth required)
#   POST /message — JSON-RPC message ingress (Bearer auth required)
```

**Terminal 2 — Run the attack orchestrator**

```bash
python src/inspector_client.py
```

### 4. Production-Grade Deployment

For a hardened deployment with TLS termination, rate limiting, and connection caps:

```bash
# Deploy behind Nginx reverse proxy
cp deploy/nginx.conf /etc/nginx/sites-available/mcp-probe
# Adjust ssl_certificate paths, then:
nginx -t && nginx -s reload

# Or run in a Linux namespace for process-level isolation
MCP_NETWORK_MODE=none bash scripts/run_sandbox.sh
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MCP_API_KEY` | `test-api-key` | Bearer token for SSE/message endpoints |
| `MCP_AUTH_DISABLE` | `0` | Set to `1` to disable auth (dev only) |
| `MCP_HITL_AUTO_APPROVE` | `0` | Set to `1` to skip human approval prompts |
| `MCP_GUARDRAIL_MODE` | `local` | `off` / `local` / `remote` |
| `MCP_GUARDRAIL_ENDPOINT` | (none) | URL for remote guardrail API |
| `MCP_LOG_LEVEL` | `DEBUG` | `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `MCP_LOG_NO_REDACT` | `0` | Set to `1` to disable telemetry redaction |

---

## 🔍 Payload Inspection: Under the Hood

We are hunting for the raw schema to see how the orchestration layer digests tool outputs. Below is the exact captured JSON-RPC data structure during a telemetry audit of the `tools/call` lifecycle:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_secure_file",
    "arguments": {
      "path": "../../etc/passwd",
      "reason": "Overriding path restrictions via semantic context injection"
    }
  },
  "id": 42
}
```

### Key Observation Points

- **Argument Bound Rigidness:** How strictly does the MCP protocol enforce type validation based on the generated Pydantic schema?
- **Context Mutation Bloat:** How much tokens/overhead does the protocol inject into the LLM context wrapper during error handling?

---

## 🛡️ Security Audit — Defense Matrix

The secure server currently passes **24/24** automated attack payloads from `exploits/payloads.json`, spanning 8 attack categories. Each payload is validated against the defense layers below.

### Implemented Defense Layers

| # | Layer | Module | What It Does |
|---|-------|--------|--------------|
| 1 | **Path Sandboxing** | `validators.py` | 7-step validation pipeline: shell-meta reject → null-byte reject → canonical resolve → join+resolve → prefix containment → symlink reject → return resolved `Path`. Per-user sandbox at `/tmp/mcp_sandbox_secure/{user_id}`. |
| 2 | **Command Injection Prevention** | `validators.py` + `security/subprocess_guard.py` + `security/command_validator.py` | Triple-layer: path-level `frozenset` blacklist (`;\|&$\`\n<>{}[]`), subprocess `shell=True` forbidden, argument whitelist (`^[A-Za-z0-9_./\-]+$`, max 4096 chars). |
| 3 | **SSRF Protection** | `validators.py` | Two-layer: string-level hostname block (127/10/192.168/172.16-31/169.254) + DNS resolution IP check via `socket.getaddrinfo()`. Closes DNS rebinding attacks. |
| 4 | **Prompt Injection Defense** | `validators.py` + `security/guardrail.py` | 4-stage output sanitization: Unicode NFKC normalization → Base64 decode & filter → injection regex detection → delimiter breakout detection. Output wrapped in `<EXTERNAL_CONTEXT>` isolation tags. Guardrail adds heuristic review for hijack/OOB patterns, with optional remote guardrail endpoint. |
| 5 | **Authentication** | `middleware/auth.py` | ASGI Bearer token middleware on `/message` and `/sse` endpoints. Configurable via `MCP_API_KEY` env var, toggleable via `MCP_AUTH_DISABLE`. |
| 6 | **Multi-Tenant Isolation** | `probe_server_secure.py` + `validators.py` | Each `user_id` gets an isolated subdirectory. `validate_sandbox_path()` locks resolution to the caller's own sandbox prefix — cross-tenant traversal is impossible regardless of `../` depth. |
| 7 | **Human-in-the-Loop (HITL)** | `security/hitl_router.py` | High-risk tools (`write_file`, `delete_file`, `execute_shell`, `send_email`) require interactive human confirmation. Bypassable via `MCP_HITL_AUTO_APPROVE=1` for automated testing. |
| 8 | **Data Loss Prevention (DLP)** | `security/dlp_scanner.py` | 7 regex patterns (AWS keys, generic API keys, China ID, SSN, email, credit cards) + redaction. Scanned on all tool outputs and telemetry reports. Log redaction for field names matching `api_key`, `password`, `secret`, `token`. |
| 9 | **Resource Exhaustion Limits** | `probe_server_secure.py` + `security/token_budget.py` | `MAX_WRITE_SIZE = 1 MB` write cap. `SessionBudget` enforces `MAX_TURNS = 20` and `MAX_ESTIMATED_TOKENS = 20_000`. Log rotation at 10 MB with 3 backups. |
| 10 | **Network Hardening** | `deploy/nginx.conf` + server config | Nginx reverse proxy with TLS 1.2/1.3, rate limiting (10 req/s, burst 20), connection limiting (10/IP), SSE timeout tuning. Server-level: `timeout_keep_alive=30`, `limit_max_requests=1000`. |
| 11 | **Process Isolation** | `security/sandbox_driver.py` + `scripts/run_sandbox.sh` | Optional Linux namespace isolation via `unshare --net --pid --fork --mount-proc`. Removes network access and isolates the process tree for third-party MCP server execution. |
| 12 | **Argument Validation** | `validators.py` + FastMCP config | `validate_required_args()` enforces known-key whitelist + required-key presence. FastMCP `strict_input_validation=True` rejects extra arguments at the framework level. |

### Attack Categories Covered

| Category | Payloads | Examples |
|---|---|---|
| SSRF | 2 | Cloud metadata endpoint probe, internal network scan |
| Command Injection | 4 | Semicolon chaining, backtick substitution, pipe to shell, ampersand bg exec |
| Path Traversal Bypass | 5 | Unicode normalization, double-write, case variation, symlink escape, long prefix |
| Timing Injection | 2 | Long path exhaustion, deep nesting traversal |
| Resource Exhaustion | 2 | Large content write, symlink loop |
| Network Layer & Auth | 4 | Missing Bearer token, DNS rebinding, cross-tenant read/write |
| Semantic Bypass | 2 | Base64-encoded injection, Unicode fullwidth injection |
| Data Exfiltration | 3 | Secrets table query, file API key leak, scraper AWS credential leak |

For the full payload catalog, see [ATTACKS.md](./ATTACKS.md). For defense mechanism details, see [PROTECT.md](./PROTECT.md).

---

## 🗺️ Current State & Roadmap

### What Works Today

- [x] **Secure MCP server:** `probe_server_secure.py` with 4 tools (read_secure_file, write_file, query_mock_db, scrape_webpage) behind 12 defense layers.
- [x] **Automated attack orchestrator:** `inspector_client.py` runs 24 payloads across 8 categories and produces a structured JSON report with DLP-redacted output.
- [x] **Core guardrails:** Path sandboxing (7-step), URL/DNS validation (2-layer), command injection prevention (3-layer), output sanitization (4-stage), prompt hijack detection, tag breakout protection.
- [x] **Authentication:** Bearer token ASGI middleware on SSE and message endpoints.
- [x] **Multi-tenant isolation:** Per-user sandbox directories with canonical path prefix locking.
- [x] **HITL gating:** Interactive human confirmation for 4 high-risk tool categories.
- [x] **DLP scanning:** 7 sensitive pattern types redacted from all tool outputs and telemetry.
- [x] **Circuit breaker:** Session-level turn and token budget enforcement.
- [x] **Network hardening:** Nginx reverse proxy config with TLS, rate limiting, and connection caps.
- [x] **Process isolation:** Optional Linux namespace sandbox via `unshare`.
- [x] **Comprehensive test suite:** 16 test modules covering every defense layer.
- [x] **Unified CLI:** `main.py` exposes `run`, `attack`, `test`, and `clean` commands.

### Open Areas for Future Hardening

- **Guardrail model integration:** `src/security/guardrail.py` has a remote endpoint placeholder — integrate Llama-Guard or a comparable safety classifier for production-grade semantic defense.

- **Dynamic rate limiting:** `deploy/nginx.conf` uses static thresholds. Per-user or adaptive rate limiting would improve resilience against coordinated attacks.
- **Audit logging:** Telemetry currently logs to local JSONL files. Integration with a centralized SIEM (e.g., Elastic, Splunk) would enable production monitoring.

---

## 🤝 Contributing

This project is intentionally minimal — we prioritize **telemetry clarity** and **exploit reproducibility** over heavy abstractions.

**Ways to contribute:**
- Submit new attack payloads to `exploits/payloads.json` (follow the existing schema with `category`, `target_tool`, `expected_outcome`, `bypass_difficulty`).
- Add new test modules in `tests/` for uncovered attack surfaces.
- Implement any open area listed in the [Roadmap](#open-areas-for-future-hardening).
- Pick up a plan from `.sisyphus/plans/` and open a draft PR.

Before writing production framework code, use this sandbox to prove your defense-in-depth strategy against real payloads.
