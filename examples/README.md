# Armorer Guard Integration Examples

These examples show the intended runtime shape:

1. inspect untrusted text before it enters an agent context
2. inspect model output before it becomes an action
3. inspect tool-call arguments before execution
4. log `reasons` and `confidence` for replayable evals

Armorer Guard is deliberately small. It does not replace least-privilege tool
permissions, approval flows, or deterministic policy. It gives those systems a
fast local risk signal.

## Examples

| File | Use case |
| --- | --- |
| `openai_agents_guard.py` | Guard OpenAI Agents SDK context ingress and function-tool arguments |
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
export ARMORER_GUARD_BIN="$PWD/target/release/armorer-guard"
```

Python examples use the local package:

```bash
python3 -m pip install -e .
python3 examples/openai_agents_guard.py
```

Node examples call the Rust binary directly and do not require an npm package.

The MCP proxy is available directly from the Rust CLI:

```bash
armorer-guard mcp-proxy -- npx some-mcp-server
```
