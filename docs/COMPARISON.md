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

## OWASP Agent Memory Guard

There is real overlap, concentrated at the memory boundary. OWASP Agent Memory
Guard is an ASI06-focused in-process Python library for protected memory keys,
prompt-injection detection, secret redaction, integrity, and memory policy.
Armorer Guard now includes those controls through supervised memory-write
targets, but its security boundary is broader: structured ingress/context/model/
action/egress supervision, workload identity, delegation, approvals, a signed
policy control plane, single-use dispatch tokens, and execution receipts.

On 2026-08-08 we ran both products against the exact 55-case corpus from OWASP
Agent Memory Guard revision `12a48f1`. Armorer exercised its persistent Unix-
socket memory endpoint with protected-key policy, encrypted evidence,
provenance, and telemetry; OWASP exercised its official in-process benchmark.

| Same upstream corpus | OWASP Agent Memory Guard | Armorer Guard |
| --- | ---: | ---: |
| Attack cases detected | 37 / 40 | 40 / 40 |
| Benign cases allowed | 15 / 15 | 15 / 15 |
| Precision | 100% | 100% |
| Recall | 92.5% | 100% |
| F1 | 0.961 | 1.000 |
| Median measured latency | 60.9 µs | 9.05 ms |

The latency row is not a like-for-like speed comparison. OWASP measures a
function call; Armorer measures a sidecar round trip plus durable runtime work.
This is a corpus regression result, not evidence of universal detection or an
independent security assessment. The reproducible adapter is
[`scripts/benchmark_agent_memory_guard.py`](../scripts/benchmark_agent_memory_guard.py)
and the captured result is
[`benchmarks/results/agent-memory-guard-head-to-head.json`](../benchmarks/results/agent-memory-guard-head-to-head.json).

## When To Use Armorer Guard

- You are building an agent that calls tools.
- You need local-only scanning with no prompt upload.
- You want JSON reasons that a runtime can enforce.
- You want to redact credentials before logs or outbound sends.
- You want local feedback without silent global model drift.

## When Not To Use It Alone

- You need OS-level resource isolation or post-execution containment.
- You rely on binary protocols that are not line-delimited stdio JSON-RPC.
- You need a hosted dashboard or managed SOC workflow out of the box.
