```markdown
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
│   ├── **init**.py
│   ├── probe_server.py      # Bare-minimum MCP Server exposing mocked filesystems/DBs
│   ├── inspector_client.py  # Host Client simulating LLM tool-calling orchestration
│   └── logger.py            # Raw JSON packet capturer & formatter
├── exploits/
│   └── payloads.json        # Test cases for Prompt Injection and Directory Traversal
├── requirements.txt
└── README.md

```

---

## 🚀 Quick Start (Telemetry Mode)

### 1. Environment Setup
```bash
# Clone the repository
git clone [https://github.com/your-username/mcp-probe-agent.git](https://github.com/your-username/mcp-probe-agent.git)
cd mcp-probe-agent

# Install minimal dependencies
pip install mcp pydantic

```

### 2. Launch the Telemetry Probe Loop

Open two terminal windows to witness the live communication:

* **Terminal 1 (The Server Side):** Exposes tools and resources.

```bash
  python src/probe_server.py

```

* **Terminal 2 (The Client/Inspector Side):** Triggers the mock LLM Agent tool execution.

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

## 🛡️ Security Audit & Framework Blast Radius Analysis

An ecosystem built on seamless, automated tool calling is a playground for remote exploits. This sandbox is actively used to simulate and patch three critical vulnerabilities:

| Threat Vector | Attack Scenario | Framework-Level Mitigation Blueprint |
| --- | --- | --- |
| **Indirect Prompt Injection** | An untrusted webpage fetched via an MCP scraper tool contains hidden text instructions that hijack the LLM's system prompt. | **Semantic Shielding:** Isolate tool outputs in non-executable data blocks; never allow raw tool returns to append directly to system instructions. |
| **Path Traversal / Argument Poisoning** | The LLM generates malicious arguments (e.g., `path: "../../../etc/passwd"`) due to jailbreaking or flawed planning loops. | **Strict Interception:** Pydantic-based regex matching and chroot-like file-path sandboxing at the framework layer *before* protocol serialization. |
| **Autonomous Mutation Exploit** | Unvalidated mutation commands (write, delete, shell execution) executing without boundary controls. | **Human-in-the-Loop (HITL) Router:** Structuring a non-blocking approval middleware. High-risk MCP tool categories require explicit CLI/UI confirmation. |

---

## 🗺️ Roadmap to Secondary Framework Development

* [x] **Phase 1:** Stand up minimal Python Client/Server architecture.
* [ ] **Phase 2:** Implement raw JSON file logging for all `resources/list`, `tools/call`, and `prompts/get` interactions.
* [ ] **Phase 3:** Simulate exploit injection payloads on local open-source LLMs to analyze context hijacking boundaries.
* [ ] **Phase 4:** Abstract these security filters into the middleware layer of our upcoming proprietary/secondary Agent framework.

## 🤝 Collab & Brainstorming

If you are an Agent architect who values security, telemetry clarity, and performance over market hype, let's connect. Open an Issue with your payload inspection logs or submit a PR for new security test cases.

```

```
