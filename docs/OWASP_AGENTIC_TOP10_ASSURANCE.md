# OWASP Agentic Top 10 assurance

Guard treats OWASP coverage as an enforceable runtime property, not a scanner
label. The executable Rust test
`runtime::tests::owasp_agentic_top10_runtime_controls_have_evidence` exercises
all ten risk families; action-layer blocks must contain a persisted
`downstream_dispatched: false` execution receipt.

| Risk | Preventive Guard control | Evidence |
| --- | --- | --- |
| ASI01 Agent Goal Hijack | Untrusted content has no instruction authority; provenance-constrained action policy | Content decision plus action non-dispatch receipt |
| ASI02 Tool Misuse & Exploitation | Boot-only capability inventory, exact resource/arguments, single-use dispatch token | Token rejection or execution receipt |
| ASI03 Identity & Privilege Abuse | Workload identity, tenant, signed delegation, approval binding | Fixed-deny receipt |
| ASI04 Agentic Supply Chain | Signed immutable policy chain, atomic snapshots, boot-only capability semantics | Signature/tamper tests and policy history |
| ASI05 Unexpected Code Execution | Undeclared code-execution capability denied; sensitive classes fail closed | Non-dispatch receipt |
| ASI06 Memory & Context Poisoning | Structured trust segments, context-source allowlist, manifest-defined protected memory targets, supervised writes | Content/provenance decision |
| ASI07 Insecure Inter-Agent Communication | Tenant and destination checks on inter-agent envelopes | Cross-tenant denial |
| ASI08 Cascading Failures | Delegation-depth bounds, request limits, dispatch rate limits, bounded telemetry | Denial/token rejection and quota tests |
| ASI09 Human-Agent Trust Exploitation | Unsupported approval/administrator claims denied before egress | Buffered output denial |
| ASI10 Rogue Agents | Guard-tampering invariant, immutable authority, identity-bound manifest | Fixed-deny receipt |

Current detection regression coverage also includes provider credentials, AWS
access keys, private-key material, SSNs, Luhn-valid payment cards, and deeply
nested, very large, or repetitive input anomalies. Detection metrics and runtime
prevention metrics must be reported
separately: a scanner hit is not proof that an effect was blocked.

Remaining production certification work is environmental: the implemented
named-pipe path must pass native Windows CI, the mutual-TLS path must be tested
in the deployment network, latency/load evidence must be captured on each
supported target, and an independent assessor must validate the full boundary.
Those gates cannot be truthfully self-certified by repository unit tests alone.
