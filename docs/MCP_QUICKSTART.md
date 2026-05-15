# MCP Quickstart

Armorer Guard can sit between an MCP client and a stdio MCP server, inspecting
`tools/call` arguments before the tool executes.

```bash
cargo install armorer-guard --locked
```

```bash
armorer-guard mcp-proxy -- npx your-mcp-server
```

## What Gets Blocked

The proxy blocks unsafe `tools/call` arguments for reasons such as:

- `detected:credential`
- `policy:credential_disclosure`
- `policy:dangerous_tool_call`
- `semantic:data_exfiltration`
- `semantic:prompt_injection`
- `learning:local_block_match`

Blocked calls return a JSON-RPC error:

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

Wrap the server command in `armorer-guard mcp-proxy --`.

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "armorer-guard",
      "args": [
        "mcp-proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/tmp"
      ]
    }
  }
}
```

## Cursor / Windsurf

Use the same shape in the MCP server config:

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

## Claude Code / Codex-Style MCP Setup

Wherever a config expects:

```json
{
  "command": "node",
  "args": ["server.js"]
}
```

change it to:

```json
{
  "command": "armorer-guard",
  "args": ["mcp-proxy", "--", "node", "server.js"]
}
```

## Node Projects

The source package under `npm/armorer-guard` provides a Node wrapper around the
Rust binary:

```js
import { requireSafeToolArgs } from "@armorer/guard";

requireSafeToolArgs("Bash", {
  command: "rm -rf /",
});
```

Until `@armorer/guard` is published, link the source package locally:

```bash
git clone https://github.com/ArmorerLabs/Armorer-Guard.git
cd Armorer-Guard/npm/armorer-guard
npm link
```

Or call the Rust binary directly from Node:

```js
import { spawnSync } from "node:child_process";

const payload = JSON.stringify({
  text: JSON.stringify({ command: "rm -rf /" }),
  context: {
    eval_surface: "tool_call_args",
    trace_stage: "action",
    policy_scope: "mcp",
    tool_name: "Bash"
  }
});

const result = spawnSync("armorer-guard", ["inspect-json"], {
  input: payload,
  encoding: "utf8"
});

console.log(JSON.parse(result.stdout));
```

## Smoke Test

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"rm -rf /"}}}' \
  | armorer-guard mcp-proxy -- python3 -c 'import sys; [print(line, end="", flush=True) for line in sys.stdin]'
```

The output should contain:

```json
{"code":-32001,"message":"Armorer Guard blocked unsafe MCP tool call"}
```
