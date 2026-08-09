# Independent security assessment scope

This repository is ready to be handed to an independent assessor; Armorer must
not self-certify the final production gate.

The assessment should test the sidecar and capability gateway as one boundary:

- Unix-socket, Windows named-pipe, and mutual-TLS authentication and isolation
- bypass attempts when the agent lacks gateway-owned credentials
- exact identity, tenant, delegation, approval, argument, and provenance binding
- single-use execution tokens and proof of non-dispatch
- policy signature, revision-chain, adaptive-tightening, rollback, and downgrade behavior
- cross-tenant context, memory, inter-agent, model, tool, and egress flows
- broker path traversal, credential-header injection, redirect, and destination bypass
- crash recovery, disk exhaustion, telemetry degradation, and concurrent dispatch
- all ten OWASP Agentic Top 10 attack and legitimate-utility traces

The assessor receives release artifacts, checksums/attestations, manifests,
policies, schemas, test fixtures, and a disposable protected downstream. They do
not need customer repositories or unrestricted customer content.

Passing evidence must include environment and artifact digests, executed test
IDs, observed receipts or downstream token rejections, latency/load results,
findings with severity and reproduction steps, remediation verification, and an
explicit statement of residual risk. Until that signed report exists, the
independent-assessment release gate remains open.
