# mcp-probe-agent — Agent Context

## Repository State (Critical)

**Skeleton repo.** Only `README.md` and `LICENSE` exist. The architecture described in the README (`src/`, `exploits/`, `requirements.txt`) has **not been implemented yet**.

- Do **not** assume source files exist. Check before editing.
- No build system, tests, CI, linting, or formatting config is present.
- No `opencode.json` or existing agent instruction files.

## Language & Dependencies

- Python.
- Intended runtime dependencies: `mcp`, `pydantic` (per README).
- No `requirements.txt`, `pyproject.toml`, or virtual env config exists yet.

## Intended Architecture (from README)

If implementing, the planned layout is:

- `src/probe_server.py` — Minimal MCP server exposing mocked tools/resources.
- `src/inspector_client.py` — Host client simulating LLM tool-calling.
- `src/logger.py` — JSON packet capture and formatting.
- `exploits/payloads.json` — Prompt injection / directory traversal test cases.

## Commands

None defined yet. The README suggests these for future use:

```bash
pip install mcp pydantic
python src/probe_server.py      # Terminal 1
python src/inspector_client.py  # Terminal 2
```

## Conventions

- This is a security research sandbox, not a production service. Code changes should prioritize telemetry clarity and exploit reproducibility over performance.
- Keep the bare-minimum Python approach; avoid heavy wrappers.
