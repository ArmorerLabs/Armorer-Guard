# Armorer Guard Launch Kit

Use this kit for launches and community replies. Keep posts technical,
specific, and useful; avoid asking directly for stars.

## Core Positioning

Armorer Guard is a fast local Rust scanner for AI agents. It runs before
untrusted text becomes context and before model output becomes a tool call.

Primary message:

> Prompt injection becomes much more dangerous when agents can execute tools.
> Armorer Guard gives agent runtimes a local pre-tool-call gate with structured
> reasons, credential redaction, and policy-friendly JSON output.

Useful links:

- GitHub: https://github.com/ArmorerLabs/Armorer-Guard
- HF model: https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier
- HF demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
- HF collection: https://huggingface.co/collections/armorer-labs/agent-safety-and-prompt-injection-guardrails-6a01f79549c39761e62a43d5

## Hacker News

Title:

```text
Show HN: Armorer Guard – fast local Rust scanning before AI-agent tool calls
```

Body:

```text
Hi HN, we built Armorer Guard, a small Rust-native scanner for AI-agent runtimes.

The idea is simple: prompt injection is not only a prompt problem once an agent
can call tools. The highest-risk moment is often right before execution, when
model output becomes a shell command, HTTP request, email, file write, or MCP
tool call.

Armorer Guard runs locally and returns structured JSON:

- sanitized_text
- suspicious
- reasons[]
- confidence

It combines deterministic credential redaction, semantic labels for prompt
injection / exfiltration / safety bypass / destructive commands, and optional
runtime context such as tool name, trace stage, surface, destination, and policy
scope.

The classifier lane is Rust-native and measured at 0.0247 ms average latency on
the validation harness. Full scanner latency also includes rules, policy checks,
normalization, and JSON IO.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
HF model: https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

I would love feedback from people building agents, MCP clients, or eval harnesses:
where would you put a pre-tool-call safety gate in your stack?
```

## Reddit Standalone Post

Title options:

```text
I built a fast local Rust scanner that gates AI-agent tool calls before execution
```

```text
Prompt injection gets scarier when agents can call tools, so I built a local pre-tool-call gate
```

Body:

```text
I have been working on Armorer Guard, a local-first scanner for AI-agent runtimes.

The thing I wanted to solve: scanning only the user prompt is not enough once
agents use tools. The risky moment is often later, when retrieved content or
model output becomes a tool-call argument, outbound payload, shell command, file
write, email, or MCP call.

Armorer Guard is written in Rust and returns structured JSON:

- sanitized_text
- suspicious
- reasons[]
- confidence

It detects prompt injection, system prompt extraction, data exfiltration,
sensitive-data requests, safety bypass attempts, destructive commands, and
credentials. The full CLI is local and does not send prompts or tool arguments to
an external scanner.

The semantic classifier lane is exported into Rust-native coefficients and
benchmarked at 0.0247 ms average classifier latency. The Python package is just a
thin wrapper around the same Rust binary.

GitHub: https://github.com/ArmorerLabs/Armorer-Guard
HF demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
HF model: https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier

I am especially looking for feedback from people building agents with tool use,
MCP, LangChain, LlamaIndex, OpenClaw/NanoClaw-style runtimes, or prompt-injection
evals. What metadata would you want the scanner to receive before a tool call?
```

## Hugging Face Discussion Reply

Use this when replying to relevant model, paper, dataset, or Space discussions:

```text
One runtime angle that may be useful here is scanning at the point where text
turns into action, not only at raw prompt ingestion.

For agent systems I would split evals by surface:

- user prompt
- retrieved content / tool output
- model output
- final tool-call arguments
- outbound payloads

The same suspicious instruction can be lower risk in retrieved text and much
higher risk once it becomes a shell command, API body, email, file write, or MCP
tool call. We are experimenting with this in Armorer Guard as a fast local
pre-tool-call gate with structured reason labels:
https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier

Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
```

## Short Social Post

```text
Prompt injection is not just a prompt problem once agents have tools.

Armorer Guard is a fast local Rust scanner that sits before tool execution and
returns structured reasons for prompt injection, exfiltration, safety bypass,
destructive commands, and credential disclosure.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
```

## Community Targets

High-fit communities:

- Hacker News `Show HN`
- Reddit: `r/LocalLLaMA`, `r/LangChain`, `r/AI_Agents`, `r/mcp`,
  `r/netsec`, `r/devsecops`, `r/cybersecurity`, `r/rust`, `r/opensource`
- Hugging Face paper/model/dataset/Space discussions
- LangChain Discord
- LlamaIndex Discord
- Hugging Face Discord
- MCP community discussions
- Rust and AppSec communities

## Commenting Rules

- Add a concrete idea before linking.
- Tie the comment to the thread's exact problem.
- Prefer questions and implementation details over slogans.
- Do not ask directly for stars.
- Do not repeat the same comment across multiple threads.
- Do not claim benchmark results beyond the README metrics.
- Do not claim production adoption unless it is public and verifiable.

