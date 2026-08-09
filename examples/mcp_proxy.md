# MCP Proxy

Armorer Guard can wrap a line-delimited stdio MCP server and inspect
`tools/call` arguments before they reach the server.

This default mode is scanner-only filtering:

```bash
armorer-guard mcp-proxy -- npx some-mcp-server
```

For identity-bound authority enforcement, run the supervision sidecar and pass
its socket to the proxy:

```bash
armorer-guard mcp-proxy \
  --sidecar-socket /run/armorer-guard/law-agent.sock \
  -- npx some-mcp-server
```

In this mode every `tools/call` must include a normalized
`params._meta.armorer_guard.authority_request`. Guard evaluates policy, consumes
the returned execution token once before forwarding, injects the token for the
protected server, and records the downstream result. Missing authority metadata
fails closed. Run [`guarded-agent/`](guarded-agent/) for a self-contained
demonstration of the same decision and receipt flow.

For a shorter first-time path, see [`docs/MCP_QUICKSTART.md`](../docs/MCP_QUICKSTART.md).

Add an audit log only when you want local JSONL receipts:

```bash
armorer-guard mcp-proxy --audit-log ~/.armorer-guard/mcp-audit.jsonl -- npx some-mcp-server
```

Blocked calls return a JSON-RPC error to the client:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Armorer Guard blocked unsafe MCP tool call",
    "data": {
      "reasons": ["policy:dangerous_tool_call"],
      "confidence": 0.94,
      "sanitized_text": "{\"command\":\"rm -rf /\"}",
      "scan_id": "sha256:..."
    }
  }
}
```

## Claude Desktop

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "armorer-guard",
      "args": ["mcp-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

## Claude Code

Use the same wrapper for any MCP server command you would normally register:

```bash
armorer-guard mcp-proxy -- your-mcp-server --stdio
```

## Cursor / Windsurf

Put `armorer-guard` in the MCP server command and move the original server
command after `--`:

```json
{
  "mcpServers": {
    "repo-tools": {
      "command": "armorer-guard",
      "args": ["mcp-proxy", "--", "node", "server.js"]
    }
  }
}
```

## NanoClaw

Run NanoClaw with `NANOCLAW_ARMORER_GUARD_BIN` for in-process inspection, or
wrap any MCP server it launches through `armorer-guard mcp-proxy`.

```bash
export NANOCLAW_ARMORER_GUARD_BIN="$(command -v armorer-guard)"
pnpm dev
```

## Local Smoke Test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"rm -rf /"}}}' \
  | armorer-guard mcp-proxy -- python3 -c 'import sys; [print(line, end="", flush=True) for line in sys.stdin]'
```
