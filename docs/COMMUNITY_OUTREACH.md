# Community Outreach Drafts

Use these when a community requires a human-owned account, manual approval, or a
conversation-first introduction. Do not ask directly for GitHub stars.

## Hacker News

Use [`SHOW_HN.md`](SHOW_HN.md).

## Lobsters

Title:

```text
Armorer Guard: local Rust scanning for AI-agent prompt injection and tool-call risk
```

Body:

```text
I built Armorer Guard, a local Rust scanner for AI-agent runtimes.

It inspects prompts, retrieved content, model output, and tool-call arguments before they become context, logs, outbound messages, or executed actions. It returns structured JSON verdicts with reasons and confidence scores for prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive-command risk, system-prompt extraction, credential disclosure, and dangerous tool-call context.

The Python package is intentionally thin and shells out to the same Rust binary. The repo includes examples for LangChain, CrewAI, MCP, Node/Express, NanoClaw, and CI smoke tests.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Benchmarks: https://github.com/ArmorerLabs/Armorer-Guard/blob/main/docs/BENCHMARKS.md
```

## OWASP GenAI / LLM Security Communities

```text
Sharing a small open-source-ish runtime scanner we built for agent security:

Armorer Guard is a local Rust scanner for prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive tool-call risk, system-prompt extraction, and credential redaction. It returns structured JSON verdicts so an agent runtime can enforce policy before context ingress, tool execution, logging, storage, or outbound sends.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo

The part I would especially like feedback on is boundary placement: pre-context, model output, tool-call args, outbound data, or all of the above.
```

## LangChain / LlamaIndex / CrewAI / MCP Discords

```text
We added a small local runtime guardrail for tool-using agents:

https://github.com/ArmorerLabs/Armorer-Guard

It is a Rust scanner that returns JSON scores/reasons for prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive command risk, system-prompt extraction, credential disclosure, and dangerous tool-call context. No scanner network calls.

There are copyable examples for LangChain, CrewAI, MCP, Node/Express, NanoClaw, and CI:
https://github.com/ArmorerLabs/Armorer-Guard/tree/main/examples

I am mainly looking for feedback from people who already run agents with tools: where would this fit best in your stack?
```

## Newsletter Pitch

```text
Subject: Fast local Rust guardrail for AI-agent prompt injection and tool-call risk

Hi,

I thought this might be relevant for your AI/security/devtools audience.

Armorer Guard is a local Rust scanner for AI-agent runtimes. It inspects prompts, retrieved content, model output, and tool-call arguments before they become context, logs, outbound messages, or executed actions. It returns structured JSON verdicts with reasons and confidence scores for prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive-command risk, system-prompt extraction, credential disclosure, and dangerous tool-call context.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Benchmarks: https://github.com/ArmorerLabs/Armorer-Guard/blob/main/docs/BENCHMARKS.md

The core is Rust-native, local-first, and includes Python, LangChain, CrewAI, MCP, Node, NanoClaw, and CI examples.
```

