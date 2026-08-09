# Armorer Guard Integration Examples

These examples cover two integration levels:

1. Scanner integrations classify and sanitize text or tool arguments.
2. The supervision sidecar enforces identity-bound authority immediately before
   dispatch and records execution receipts.

The scanner is a risk signal, not authorization. The sidecar adds strict policy,
delegation verification, approval binding, single-use execution tokens, and
receipts. It still does not replace OS sandboxing: protected capabilities and
credentials must be reachable only through a Guard-mediated gateway.

## Examples

| File | Use case |
| --- | --- |
| `guarded-agent/` | Run a real OpenAI Agents SDK agent with Guard-enforced tools, approval, tokens, and receipts |
| `langchain_guard.py` | Wrap LangChain retrieved content and tool arguments |
| `crewai_guard.py` | Guard a CrewAI tool before execution |
| `node_middleware.mjs` | Use the Rust binary from Node/Express or Vercel-style handlers |
| `mcp_proxy.md` | Wrap a line-delimited stdio MCP server with the Rust proxy |
| `mcp_tool_gate.py` | Gate MCP tool calls before forwarding them to a server |
| `claude-code-hook.md` | Pre-tool-call hook pattern for Claude Code-style workflows |
| `cursor-mcp.md` | Cursor and Windsurf MCP wrapper snippets |
| `nanoclaw.md` | Run NanoClaw with and without Armorer Guard side by side |
| `github-action.yml` | CI smoke test for prompt/tool-call fixtures |

## Local Setup

From the repository root:

```bash
cargo build --release
```

Run the complete live guarded-agent demonstration first:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r examples/guarded-agent/requirements.txt
export BWS_OPENROUTER_SECRET_ID='your-bitwarden-secret-uuid'
PYTHONPATH=.:examples/guarded-agent .venv/bin/python examples/guarded-agent/run.py
```

The live script uses the OpenAI Agents SDK with OpenRouter and DeepSeek V4 Flash
0731, loading the API credential from Bitwarden Secrets Manager or
`OPENROUTER_API_KEY`. It creates an isolated temporary Guard configuration and
removes it after the sidecar exits. The security-contract test under
`guarded-agent/tests/` remains offline and credential-free.

The smaller Python examples also use the local package:

```bash
python3 -m pip install -e .
```

The source-tree Python wrapper finds `target/release/armorer-guard` directly.
Node examples use `ARMORER_GUARD_BIN` when set and otherwise resolve
`armorer-guard` from `PATH`.

The MCP proxy is available directly from the Rust CLI:

```bash
armorer-guard mcp-proxy -- npx some-mcp-server
```

That command enables scanner-only MCP filtering. Add `--sidecar-socket` and an
identity-bound authority request for full pre-dispatch enforcement; see
[`mcp_proxy.md`](mcp_proxy.md).
