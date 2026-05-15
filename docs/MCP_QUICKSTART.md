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

Typical config locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

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

Use separate `args` entries instead of a single shell-quoted command string. If
your MCP server needs a path with spaces, keep it as one JSON array item, for
example `"/Users/alex/Client Work"`.

## Cursor / Windsurf

Use the same `command` plus `args` shape in the MCP server config.

Typical config locations:

- Cursor global MCP config: `~/.cursor/mcp.json`
- Cursor project MCP config: `.cursor/mcp.json`
- Windsurf global MCP config: `~/.codeium/windsurf/mcp_config.json`
- Windsurf project MCP config: `.windsurf/mcp_config.json`

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

Keep `mcp-proxy`, `--`, and every wrapped server argument as separate array
entries. This avoids shell-specific quoting differences between desktop apps and
lets the app launch the stdio server directly.

## Validation Output

The quickstart shape launches a wrapped line-delimited stdio MCP server. These
local smoke tests show one unsafe `tools/call` blocked by Armorer Guard and one
safe call forwarded to the wrapped server.

Blocked unsafe call:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"rm -rf /"}}}' \
  | armorer-guard mcp-proxy -- python3 -c 'import sys; [print(line, end="", flush=True) for line in sys.stdin]'
```

Expected output contains a JSON-RPC error from the proxy instead of output from
the wrapped server:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Armorer Guard blocked unsafe MCP tool call","data":{"reasons":["policy:dangerous_tool_call"],"confidence":0.94,"sanitized_text":"{\"command\":\"rm -rf /\"}","scan_id":"sha256:..."}}}
```

Allowed safe call:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes.write","arguments":{"path":"notes.txt","content":"ship the checklist"}}}' \
  | armorer-guard mcp-proxy -- python3 -c 'import sys; [print(line, end="", flush=True) for line in sys.stdin]'
```

Expected output is the original request echoed by the wrapped test server,
showing the proxy forwarded it:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes.write","arguments":{"path":"notes.txt","content":"ship the checklist"}}}
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

```bash
npm install @armorerlabs/guard
```

```js
import { requireSafeToolArgs } from "@armorerlabs/guard";

requireSafeToolArgs("Bash", {
  command: "rm -rf /",
});
```

If `@armorerlabs/guard` is not visible in your registry yet, link the source package
locally:

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
