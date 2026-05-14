# Claude Code Hook Pattern

Use Armorer Guard before high-risk tools run. The exact hook surface depends on
your Claude Code setup, but the enforcement shape is the same: serialize the
tool arguments, scan them with MCP/action context, then block on dangerous
reasons.

```bash
payload='{"text":"{\"command\":\"rm -rf /\"}","context":{"eval_surface":"tool_call_args","trace_stage":"action","tool_name":"Bash"}}'
printf '%s' "$payload" | armorer-guard inspect-json
```

Block when the verdict contains any of:

```text
detected:credential
policy:credential_disclosure
policy:dangerous_tool_call
semantic:data_exfiltration
semantic:prompt_injection
learning:local_block_match
```

For MCP-backed tools, prefer the drop-in proxy:

```bash
armorer-guard mcp-proxy -- your-claude-code-mcp-server --stdio
```
