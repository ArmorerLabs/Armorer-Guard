# Show HN Draft

Title:

```text
Show HN: Armorer Guard, a local Rust scanner for AI-agent prompt injection
```

URL:

```text
https://github.com/ArmorerLabs/Armorer-Guard
```

Text:

```text
I built Armorer Guard, a local-first Rust scanner for AI-agent security boundaries: prompts, retrieved content, model output, tool-call arguments, logs, memory writes, and outbound messages.

It returns structured JSON with redacted text, reasons, and confidence for prompt injection, system prompt extraction, exfiltration, sensitive-data requests, safety bypasses, destructive command intent, credential leakage, and risky tool-call arguments.

The semantic lane is a Rust-native TF-IDF linear classifier exported from public Hugging Face artifacts. Current snapshot: 0.0247 ms average classifier latency, 0.9833 macro F1, 0.9819 micro F1, 1,411 validation rows.

Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Attack fixtures: https://github.com/ArmorerLabs/Armorer-Guard/blob/main/docs/ATTACK_EXAMPLES.md
PyPI: https://pypi.org/project/armorer-guard/

I am looking for feedback from people building agents: where would you put this check, what would you expect it to catch, and what false positives would make it unusable?
```
