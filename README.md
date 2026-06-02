# mcp-probe-agent

A lightweight, Python-based probe environment designed to dissect Anthropic's Model Context Protocol (MCP), inspect payload structures, and audit security vulnerabilities before full-scale LLM Agent framework development.

---

## ⚡ Why This Repository Exists (The TL;DR)

While the Model Context Protocol (MCP) can sometimes feel over-engineered, it has become the undeniable gravitational well for open-source LLM tools and data sources. To build a robust, production-ready Agent framework, you cannot bypass it. 

This repository serves as a **lightweight sandbox** to:
1. **Minimize Setup Overhead:** Spin up MCP servers/clients instantly using minimal Python.
2. **Expose Raw JSON Payloads:** Inspect the exact data structures flying over the wire.
3. **Audit Security Vulnerabilities:** Map out critical attack vectors (Prompt Injection, Path Traversal) to prepare our core framework's defense layer (e.g., Human-in-the-Loop gating).

---

## 🏗️ Architecture & Quick Start

This sandbox implements a minimal MCP Client-Server loop using the official `mcp` Python SDK to intercept and log every single JSON-RPC 2.0 packet.

### 1. Prerequisites
```bash
pip install mcp pydantic
2. Run the Probe Server
A bare-minimum server exposing a mocked filesystem or database tool to inspect parameter bindings.
Bash
python src/probe_server.py
3. Run the Inspector Client
Simulate an LLM orchestrating the tool call and capture the raw payloads.
```Bash
python src/inspector_client.py
🔍 Payload Inspection (What We Are Looking At)
We are hunting for the raw schema to see how LLMs digest tool outputs. The focus is on capturing the exact JSON-RPC structure during the tools/call lifecycle:
JSON
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_secure_file",
    "arguments": {
      "path": "../../etc/passwd" 
    }
  },
  "id": 42
}
Intercepting this allows us to design precise serialization layers for our upcoming Agent framework.

---
🛡️ Security Audit & Blast Radius Analysis
An ecosystem built on seamless tool calling is a breeding ground for remote code execution and data exfiltration. This repository is actively used to map out defenses against three critical threat vectors:
1. Indirect Prompt Injection
The Risk: An external data source (e.g., an untrusted webpage fetched via an MCP tool) contains malicious instructions that hijack the LLM's system prompt.
Framework Defense: Implementation of semantic shields and strict output validation before passing MCP data back to the LLM context.
2. Path Traversal & Argument Sanitization
The Risk: The LLM generates malicious arguments (e.g., path: "/../../../etc/passwd") due to jailbreaking or flawed planning.
Framework Defense: Strict Pydantic-based regex matching and chroot-like path sandboxing at the framework layer before hitting the MCP protocol bridge.
3. Human-in-the-Loop (HITL) Routing
The Risk: Unvalidated mutations (write, delete, shell execution) executing autonomously.
Framework Defense: Mapping out a non-blocking approval gateway. Designing a structural middleware where sensitive MCP tools require explicit user confirmation via a CLI/Web UI prompt.

---
🗺️ Roadmap to Agent Framework Integration
[ ] Phase 1: Complete raw JSON telemetry capturing for resources, tools, and prompts.
[ ] Phase 2: Simulate exploit payloads (Prompt Injection) on local LLMs to test context hijacking.
[ ] Phase 3: Extract sanitized schemas and abstract them into our core, production-grade Agent framework.

---
🤝 Collaboration & Contribution
If you are building Agent architectures and refuse to trust third-party protocol abstractions blindly, feel free to open an Issue or submit a PR with your security findings.
