# Show HN Draft

Title:

```text
Show HN: Armorer Guard, a fast local Rust scanner for AI-agent prompt injection
```

Post:

```text
Hi HN,

I built Armorer Guard, a local Rust scanner for AI-agent runtimes. It inspects prompts, retrieved content, model output, and tool-call arguments before they become context, logs, outbound messages, or executed actions.

It returns structured JSON verdicts with reasons and confidence scores for prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive-command risk, system-prompt extraction, credential disclosure, and dangerous tool-call context.

The design goal is not “one magic guardrail.” It is a fast local signal you can combine with deterministic policy, least-privilege tools, approval flows, and replayable eval traces.

Repo: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Model artifact: https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier
Demo GIF: https://raw.githubusercontent.com/ArmorerLabs/Armorer-Guard/main/docs/assets/armorer-guard-demo.gif

The scanner core is Rust-native, makes no network calls, and the Python package is just a thin wrapper around the same binary. Current exported classifier snapshot: 0.0247 ms average classifier latency, 0.9833 macro F1, 0.9819 micro F1, 1.0000 micro recall, 0.9724 exact match on 1,411 validation rows.

I would especially like feedback from people building agents with tool use, MCP servers, browser/file/email tools, or retrieval over untrusted content. Where would you put this boundary in your stack?
```

## Hacker News Notes

- Post from a personal account, not a brand account.
- Be ready to answer licensing questions clearly: noncommercial source-available,
  paid commercial license.
- Do not ask for stars.
- Link the demo and benchmarks in the first comment if the main post feels too
  link-heavy.
