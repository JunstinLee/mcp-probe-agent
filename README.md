# mcp-probe-agent

A lightweight, Python-based probe environment and security sandbox designed to dissect Anthropic's Model Context Protocol (MCP), inspect raw JSON telemetry, and audit exploit vectors before full-scale Agent framework secondary development.

---

## ⚡ Why This Repository Exists (The Strategic TL;DR)

While the Model Context Protocol (MCP) can sometimes feel like an over-engineered hype-train, it has undeniably become the gravitational well for open-source LLM tools and data sources. To build a highly compatible, next-generation Agent framework, you simply cannot bypass it. 

However, trusting third-party protocol abstractions blindly is a recipe for architectural disaster. This repository serves as a **zero-overhead telemetry sandbox** to achieve three tactical goals:

1. **Unmask the Protocol:** Use a bare-minimum Python implementation to strip away the fluff and expose the raw JSON-RPC 2.0 payloads.
2. **Telemetry Inspection:** See *exactly* what data structures, schemas, and metadata are flying over the wire when an LLM requests a tool or resource.
3. **Security Defusal:** Map out critical threat vectors (Indirect Prompt Injection, Path Traversal) and establish framework-level defense blueprints (e.g., Human-in-the-Loop gating) before writing a single line of production framework code.

---

## 🏗️ Architecture & Component Layout

This sandbox bypasses complex wrappers, using the official `mcp` Python SDK to intercept and log every single network packet into a readable telemetry stream.

```
mcp-probe-agent/
├── src/
│   ├── __init__.py
│   ├── probe_server_secure.py   # Secure MCP Server (port 8766) — hardened
│   ├── inspector_client.py      # Attack orchestrator
│   ├── logger.py                # Raw JSON packet capturer & formatter
│   ├── validators.py            # Path sandboxing, URL validation, output sanitization
│   └── cli/
│       ├── commands.py          # CLI subcommand implementations
│       └── __init__.py
├── tests/
│   ├── test_path_traversal.py
│   ├── test_prompt_injection.py
│   ├── test_input_validation.py
│   ├── test_integration.py
│   └── test_smoke.py
├── exploits/
│   └── payloads.json            # 15 automated attack payloads
├── .sisyphus/plans/             # Security hardening roadmaps (4 plans)
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

# Install dependencies (uses uv or pip)
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
#   GET  /sse     — SSE event stream
#   POST /message — JSON-RPC message ingress
```

**Terminal 2 — Run the attack orchestrator**

```bash
python src/inspector_client.py
```

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

### Key Observation Points:

* **Argument Bound Rigidness:** How strictly does the MCP protocol enforce type validation based on the generated Pydantic schema?
* **Context Mutation Bloat:** How much tokens/overhead does the protocol inject into the LLM context wrapper during error handling?

---

## 🛡️ Security Audit — Defense Matrix

The secure server (`probe_server_secure.py`) currently passes **15/15** automated attack payloads from `exploits/payloads.json`. Below is the full breakdown of what is solved versus what remains open.

### ✅ Solved (Input & Tool Execution Layer)

| # | Threat | Mitigation in Code | Test File |
|---|--------|-------------------|-----------|
| 1 | **Path Traversal** | `validate_sandbox_path()` — `Path.resolve()` + `is_relative_to()` sandbox locking | `tests/test_path_traversal.py` |
| 2 | **Symlink Escape** | `os.path.islink()` — rejects all symlinks before access | `tests/test_path_traversal.py` |
| 3 | **Command Injection** | No `shell=True` / `os.system()` present; relies on absence rather than explicit guardrail | *no dedicated test* |
| 4 | **Application DoS** | `MAX_WRITE_SIZE = 1 MB` hard limit on writes | `tests/test_path_traversal.py` |
| 7 | **SSRF (Basic)** | `validate_url()` regex blocks private ranges (`127/10/192.168/172.16-31/169.254`) | `tests/test_input_validation.py` |
| 10 | **Prompt Injection (Basic)** | `sanitize_output()` — regex filters English trigger words + wraps output in `<tool_output>` tags | `tests/test_prompt_injection.py` |

### ⚠️ Partial / No-Test Coverage

| # | Threat | Status | Note |
|---|--------|--------|------|
| 3 | **Command Injection** | ⚠️ *Security by absence* | No explicit `subprocess_guard` or shell-metacharacter blacklist yet |
| 10 | **Prompt Injection (Non-English)** | ⚠️ *Structural only* | `<tool_output>` wrapping works, but regex cannot catch multi-language / Base64 / obfuscated injections |

### ❌ Not Yet Implemented

| # | Threat | Why It Matters |
|---|--------|----------------|
| 5 | **Unauthorized Access (Broken AuthZ)** | SSE endpoints are wide open — no Bearer Token or API Key |
| 6 | **Network DoS / Slowloris** | No reverse proxy (Nginx/Caddy), no `limit_conn`, no connection timeout hardening |
| 8 | **Advanced SSRF (DNS Rebinding)** | `validate_url()` only checks the hostname string; does not resolve DNS and validate the resulting IP at socket level |
| 9 | **Multi-tenant Data Leak** | Single shared sandbox dir (`/tmp/mcp_sandbox_secure`) — no per-user / per-session physical isolation |
| 11 | **Persona Adoption / Virtual Hijacking** | No Human-in-the-Loop (HITL) — high-risk tools execute without pause for human confirmation |
| 12 | **Semantic Escape / Obfuscation** | No Guardrail model (e.g., Llama-Guard) — static regex is inherently bypassable |
| 13 | **Economic Attack (Infinite Loop)** | No `max_turns` limit, no token-budget circuit breaker in the orchestrator |
| 14 | **Supply Chain Poisoning** | No Docker sandbox — third-party MCP Servers run in the same OS process as the host |
| 15 | **Covert Channel Data Exfiltration** | No DLP scanner — sensitive patterns (AWS keys, SSN, credit cards) are not masked before results reach the LLM or external output |

---

## 🗺️ Current State & Roadmap

### What Works Today

- [x] **Secure MCP server:** `probe_server_secure.py` with hardened input validation and output sanitization.
- [x] **Automated attack orchestrator:** `inspector_client.py` runs 15 payloads against the secure server and produces a JSON report.
- [x] **Core guardrails:** Path sandboxing, symlink rejection, URL private-range blocking, write-size limits, basic prompt-injection regex filtering.
- [x] **Comprehensive test suite:** 5 test modules covering path traversal, prompt injection, input validation, integration, and smoke tests.
- [x] **Unified CLI:** `main.py` exposes `run`, `attack`, `test`, and `clean` commands.

## 🤝 Contributing

This project is intentionally minimal — we prioritize **telemetry clarity** and **exploit reproducibility** over heavy abstractions.

**Ways to contribute:**
- Submit new attack payloads to `exploits/payloads.json` (follow the existing schema).
- Implement any open item from the [Security Matrix](#-security-audit--defense-matrix) above.
- Pick up a plan from `.sisyphus/plans/` and open a draft PR.

Before writing production framework code, use this sandbox to prove your defense-in-depth strategy against real payloads.
