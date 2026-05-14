# Cursor And Windsurf MCP Wrapper

Armorer Guard works best at the tool-call boundary. For Cursor or Windsurf MCP
servers, keep the server config but wrap the command through the Guard proxy.

Before:

```json
{
  "mcpServers": {
    "repo-tools": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}
```

After:

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

For local audit receipts:

```json
{
  "mcpServers": {
    "repo-tools": {
      "command": "armorer-guard",
      "args": ["mcp-proxy", "--audit-log", ".armorer-guard-mcp-audit.jsonl", "--", "node", "server.js"]
    }
  }
}
```
