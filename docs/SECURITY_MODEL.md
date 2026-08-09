# Security Model

Armorer Guard is a local agent supervision and capability enforcement runtime.
It does not replace OS sandboxing. Versioned
`armorer-guard-policy-bundle/v1` policies can enforce least-privilege decisions
for trusted identity, delegation, action, and resource context before a host
executes a tool.

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

## Enforcement Boundary

- It is not an OS sandbox. Protected effects require the capability gateway,
  isolated credentials, and egress controls; a convenience wrapper is not a
  security boundary when an agent retains an unwrapped credential.
- Text inspection is never authorization. Action Guard consumes an exact
  `armorer-guard-authority-request/v2`; an allow yields a signed token, which
  must be atomically consumed before dispatch and receipted after the outcome.
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

## Identity Policy Boundary

`armorer-guard policy-evaluate` consumes a versioned policy bundle and an exact
authority request. Decisions bind the agent identity, runtime identity, tenant,
delegator, capabilities, purpose, action, resource, provenance, approvals, and
delegation lifetime.

Fixed invariants always deny cross-tenant access, unsigned or expired
delegation, Guard tampering, and untrusted privilege expansion. Adaptive policy
is `tightening_only`: it may deny or require approval at elevated risk, but it
can never grant or expand authority. Allow rules must bind a concrete agent or
identity and require a capability or explicit approval.

Raw retained evidence is encrypted locally with ChaCha20-Poly1305 and is not
included in exported telemetry. Telemetry contains content hashes, provenance,
identity/resource references, policy decisions, reason codes, and enforcement
outcomes. The local spool is bounded and rotated; ordinary enforcement has no
network dependency.

Full authority requests retained for deterministic replay are encrypted in a
separate local spool with bounded retention. Replay re-evaluates policy only; it
does not issue a token or dispatch an effect. Credential-owning HTTP brokers
reject redirects and agent-supplied authentication headers, inject the exact
signed execution token for downstream verification, and never return the
protected credential to the agent.
