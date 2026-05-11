# Discovery Submissions

This tracker is for durable visibility channels: places where agent builders and
security engineers browse for tools after launch day.

## Primary Links

- Repo: https://github.com/ArmorerLabs/Armorer-Guard
- Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
- Model: https://huggingface.co/armorer-labs/armorer-guard-semantic-classifier
- Screenshot: https://raw.githubusercontent.com/ArmorerLabs/Armorer-Guard/main/docs/assets/armorer-guard-demo-sensitive-data.png
- Demo GIF: https://raw.githubusercontent.com/ArmorerLabs/Armorer-Guard/main/docs/assets/armorer-guard-demo.gif

## Short Description

Fast local Rust scanner for AI-agent prompt injection, sensitive-data requests,
exfiltration, safety bypass, destructive tool-call risk, and credential
redaction.

## Long Description

Armorer Guard is a local-first Rust scanner for AI-agent runtimes. It inspects
prompts, retrieved content, model output, and tool-call arguments before they
become context, logs, outbound messages, or executed actions. It returns
structured JSON verdicts with reasons and confidence scores for prompt
injection, system-prompt extraction, sensitive-data requests, exfiltration-style
text, safety bypass, destructive-command risk, credential disclosure, and
dangerous tool-call context. Python support is included through a thin wrapper
around the Rust binary.

## Submission Targets

| Target | Fit | Status | Notes |
| --- | --- | --- | --- |
| AgDex | AI agent tooling directory | pending | https://agdex.ai/ |
| Agent Hub | AI agents, MCPs, skills | pending | https://agent-hub.dev/ |
| DeepYard | Open-source AI agent ecosystem | submitted | Formspree accepted `ok=true` on 2026-05-11 |
| AISecTools | Open-source AI security tools | discoverability updated | Added GitHub topics: `ai-security`, `ai-security-tool`, `agent-security`, `security-scanner`, `secrets-detection`, `mcp-security` |
| Vulnify | Open-source security tools | discoverability updated | Added GitHub topic: `vulnify`; no public submit form found |
| AgentDir | AI agent/tool directory | blocked | Submission page requires login |
| AgentsTide | AI agent directory | blocked | Submission is mailto-only; email draft below |
| Hacker News | technical launch | blocked | Submit page requires login; Safari has a saved account prompt but manual credential approval is needed |
| Lobsters | programming/security launch | blocked | Requires login/invitation-backed account |
| OWASP GenAI | community/resource mention | draft | Best through a useful resource thread |
| ProjectRecon/awesome-ai-agents-security | curated GitHub list | PR opened | https://github.com/ProjectRecon/awesome-ai-agents-security/pull/31 |
| tldrsec/prompt-injection-defenses | curated GitHub list | PR opened | https://github.com/tldrsec/prompt-injection-defenses/pull/19 |
| LLMSecurity/awesome-agent-skills-security | curated GitHub list | PR opened | https://github.com/LLMSecurity/awesome-agent-skills-security/pull/3 |
| DevTool Center | developer tools directory | submitted | API accepted pending submission `_id=6a025da33680f218e1982b97` on 2026-05-11 |
| Joe-B-Security/awesome-prompt-injection | curated GitHub list | PR opened | https://github.com/Joe-B-Security/awesome-prompt-injection/pull/48 |
| TalEliyahu/Awesome-AI-Security | curated GitHub list | PR opened | https://github.com/TalEliyahu/Awesome-AI-Security/pull/68 |
| beyefendi/awesome-llm-security | curated GitHub list | PR opened | https://github.com/beyefendi/awesome-llm-security/pull/8 |

## Email Draft For Mailto-Only Directories

Subject:

```text
Agent submission: Armorer Guard
```

Body:

```text
Hi,

I'd like to submit Armorer Guard for your AI agent/security tools directory.

Name: Armorer Guard
URL: https://github.com/ArmorerLabs/Armorer-Guard
Demo: https://huggingface.co/spaces/armorer-labs/armorer-guard-demo
Category: AI agent security / guardrails / developer tool

Description:
Armorer Guard is a fast local Rust scanner for AI-agent prompt injection, sensitive-data requests, exfiltration-style text, safety bypass, destructive tool-call risk, and credential redaction. It returns structured JSON verdicts with reasons and confidence scores, and includes Python, LangChain, CrewAI, MCP, Node, NanoClaw, and CI examples.

Screenshot:
https://raw.githubusercontent.com/ArmorerLabs/Armorer-Guard/main/docs/assets/armorer-guard-demo-sensitive-data.png

Thanks,
Armorer Labs
```
