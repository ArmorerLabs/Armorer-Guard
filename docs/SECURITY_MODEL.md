# Security Model

Armorer Guard is a local risk signal and enforcement helper for AI-agent
boundaries. It does not execute tools, replace sandboxing, or replace
least-privilege permissions.

## What Guard Catches

- Prompt injection and instruction override attempts.
- System prompt extraction and guardrail bypass requests.
- Credential disclosure and common provider token leaks.
- Data exfiltration language in prompts, retrieved content, model output, and tool arguments.
- Dangerous tool-call context such as destructive shell commands.
- Local deployment feedback through the Learning Loop.

## Where To Put It

Use Guard at boundaries where untrusted or model-generated text becomes more
powerful:

| Boundary | Guard surface |
| --- | --- |
| Retrieval ingress | scan retrieved pages, files, emails, tickets, or browser text before context insertion |
| Model output | scan responses before posting, storing, or turning them into actions |
| Tool-call arguments | scan JSON args before file, shell, browser, database, email, or MCP calls |
| Outbound sends | scan Slack, email, webhook, PR, issue, or API payloads |
| Memory writes | scan proposed memories before persistence |

## What Guard Does Not Catch

- It is not a sandbox and cannot contain a tool after it executes.
- It is not an authorization system and cannot decide who may access a resource.
- It does not make scanner network calls or consult a cloud model at runtime.
- MCP proxy v1 expects line-delimited stdio JSON-RPC, not Content-Length framed transport.
- The semantic model is lightweight and local; use logs and feedback to tune deployment policy.

## Learning Loop Boundary

Local feedback can add allow, block, or review exemplars under
`~/.armorer-guard/feedback` or `ARMORER_GUARD_HOME`. It can suppress eligible
semantic noise for strong local allow matches, but it cannot suppress:

```text
detected:credential
policy:credential_disclosure
policy:dangerous_tool_call
```

Unreviewed feedback stays local and must not train the public model. Reviewed
exports should go through secret scanning, dedupe, provenance checks, and human
review before offline retraining.
