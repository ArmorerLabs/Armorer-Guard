# Marketing Playbook

## Core Message

Armorer Guard is a fast local Rust security layer for AI agents and MCP tool
calls. It detects prompt injection, credential leakage, exfiltration, and
dangerous actions before they execute. No scanner network calls.

Secondary message:

The Learning Loop lets teams adapt local enforcement from feedback without
silent model drift or poisoning-by-default.

## Launch Assets

- 90-second video: MCP call blocked, credential redacted, Learning Loop applied, dangerous action still blocked.
- 15-second GIF for README and social posts.
- Agent-boundary diagram: retrieval ingress, model output, tool-call args, outbound sends, memory writes.
- Benchmark card: `0.0247 ms` classifier latency, local-first, structured reasons.

## Copy-Paste Post

I’m building Armorer Guard, a local Rust security layer for AI agents and MCP
tool calls.

It scans prompts, retrieved content, model output, and tool-call arguments for
prompt injection, credential leakage, exfiltration, and dangerous actions before
they execute. It returns structured JSON reasons, redacts secrets, and makes no
scanner network calls.

The newest piece is an MCP proxy:

```bash
armorer-guard mcp-proxy -- npx some-mcp-server
```

I’m looking for feedback from people building agents: where would you insert
this check, and what false positives would make it unusable?

Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Repo: https://github.com/ArmorerLabs/Armorer-Guard

## Outreach Rules

- Do not ask directly for stars in comments.
- Ask for concrete feedback.
- Link to the demo first for cold audiences.
- Keep comments high-fit and non-duplicative.
