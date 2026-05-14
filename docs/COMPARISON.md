# Comparison

Armorer Guard is a fast local runtime layer for agent boundaries. It is meant to
work alongside red-team tools, eval frameworks, sandboxes, and policy engines.

| Tool type | Use it when | How Armorer Guard fits |
| --- | --- | --- |
| LLM Guard-style scanners | You need broad input/output scanners and Python-native policy | Use Guard when you want a tiny Rust binary, structured reasons, and local tool-call checks |
| Garak / red-team scanners | You want to find weaknesses before shipping | Use Guard in the runtime path after testing exposes risky boundaries |
| Promptfoo | You need repeatable evals and regression gates | Use Promptfoo to evaluate, then use Guard reasons in app or MCP enforcement |
| MCP scanners | You want to audit installed MCP servers and metadata | Use Guard to inspect live `tools/call` arguments before execution |
| Regex filters | You need simple deterministic blocks | Use Guard when prompt injection, exfiltration, and context-aware policy need semantic signals |
| Sandboxes / permissions | You need hard containment | Keep them; Guard provides an early warning and structured block before the sandbox is needed |

## When To Use Armorer Guard

- You are building an agent that calls tools.
- You need local-only scanning with no prompt upload.
- You want JSON reasons that a runtime can enforce.
- You want to redact credentials before logs or outbound sends.
- You want local feedback without silent global model drift.

## When Not To Use It Alone

- You need formal authorization, resource isolation, or post-execution containment.
- You rely on binary protocols that are not line-delimited stdio JSON-RPC.
- You need a hosted dashboard or managed SOC workflow out of the box.
