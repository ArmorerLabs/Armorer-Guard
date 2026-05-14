# Armorer Guard v0.2.3 Launch Posts

## Short Reddit / GitHub Discussion Post

I built Armorer Guard, a local Rust security layer for AI agents and MCP tool
calls.

The newest release adds an MCP proxy:

```bash
armorer-guard mcp-proxy -- npx your-mcp-server
```

It sits between an agent and a stdio MCP server, gates `tools/call` arguments,
and blocks prompt injection, credential leakage, exfiltration, and dangerous
actions before the tool executes. It returns structured JSON reasons and makes
no scanner network calls.

Live demo:
https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

Repo:
https://github.com/ArmorerLabs/Armorer-Guard

Demo GIF:
https://github.com/ArmorerLabs/Armorer-Guard/blob/main/docs/assets/armorer-guard-v023-mcp-demo.gif

I am looking for feedback from people building agents: where would you put this
check, and what false positives would make it unusable?

## Technical Comment

For MCP/tool-using agents, I think the most useful insertion point is right
before `tools/call`, not only at user input. Retrieved content and model output
can look harmless until they become tool arguments.

I have been building Armorer Guard around that shape. The `0.2.3` release adds:

- `armorer-guard mcp-proxy -- ...`
- structured JSON reasons and scan IDs
- credential redaction
- local feedback overlay for false-positive tuning
- no scanner network calls

Demo:
https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

MCP proxy docs:
https://github.com/ArmorerLabs/Armorer-Guard/blob/main/examples/mcp_proxy.md

Curious where you would enforce this boundary in your stack: MCP proxy, agent
hook, framework middleware, or all three?

## Hugging Face Community Post

Armorer Guard now has a Space demo for the `0.2.3` runtime release:

https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

The demo includes preset cases for prompt injection, credential leakage, MCP
tool-call risk, benign false positives, and the Learning Loop.

The runtime is local Rust and designed for agent boundaries:

- retrieval ingress
- model output
- MCP `tools/call` arguments
- outbound sends
- memory writes

No scanner network calls. Local feedback can adapt enforcement without mutating
classifier weights or training the public model by default.

## DEV.to Follow-Up Comment

The live demo now has MCP/tool-call and Learning Loop presets:

https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

The most useful feedback would be concrete integration shape: would you rather
use this as an MCP proxy, a pre-tool hook, framework middleware, or a library
call inside your agent runtime?
