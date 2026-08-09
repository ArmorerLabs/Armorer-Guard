# Operating the Guard sidecar

Guard is a workload-local security service. Run one manifest-bound instance per
agent identity. The agent connects over a mode-`0600` Unix socket (or a local
Windows named pipe); remote mode requires mutual TLS and a private network.

## Service lifecycle

Linux operators can install `packaging/systemd/armorer-guard@.service`, create a
dedicated `armorer-guard` user, and enable an instance with:

```text
systemctl enable --now armorer-guard@law-agent
```

macOS operators can copy the launchd example, replace `AGENT_ID`, and load it as
a system LaunchDaemon. Windows deployments should install the release binary as
a restricted service account and configure `transport.kind` as
`windows_named_pipe`; the pipe name must start with `\\.\pipe\`.

Before every start or upgrade, run `armorer-guard validate --config ...`. A
failed validation, unreadable key, invalid signature, or discontinuous policy
revision prevents readiness. Health remains available for diagnosis.

## Upgrade and rollback

Release artifacts are checksummed and build-provenance attested. Verify those
artifacts before replacing the binary. Stop one sidecar instance, retain its
data directory and last-known-good policy, replace the binary atomically, then
start and wait for `/v1/readiness` before returning the agent to service.

Persistent JSON fields added within a schema version use conservative defaults.
Unknown fields from a newer writer fail closed. Never downgrade across a schema
version without the corresponding migration tool and a tested data-directory
copy. Policy rollback uses `/v1/policies/rollback`; binary rollback restores the
previous verified artifact while retaining the compatible state directory.

## Disk pressure and recovery

Telemetry is split into two bounded segments and rotates under its manifest
quota. Telemetry write failure marks `/v1/health` as `telemetry: degraded` but
does not turn an already-enforced action into a retry. Execution receipts and
atomic enforcement snapshots remain authoritative. State snapshots are written,
synced, renamed, and directory-synced; an interrupted temporary file cannot
replace the last-known-good snapshot.

If disk pressure persists, stop the agent first, preserve receipt and policy
state, export or remove expired evidence under the organization retention
procedure, and restart Guard. Never delete the active enforcement snapshot to
recover space.

`GET /v1/operations/status` reports queue bytes and pressure, effective versus
bootstrap policy revision, staged and rollback-capable revisions, in-flight
effects, open circuits, and declared unmediated capabilities. This is the
dashboard source; alert on degraded telemetry, nonzero open circuits or bypass
frontiers, and unexpected policy divergence.

## SLOs and alerts

Measure locally at the socket boundary after warm-up. Required targets are:

Use `scripts/benchmark_sidecar.py` against a running example-compatible
sidecar to emit p50/p95/p99 JSON evidence. Production certification repeats the
measurement on every supported operating system and deployment shape.

| Signal | Target | Alert response |
| --- | ---: | --- |
| Action evaluation p95 | < 10 ms | Stop sensitive dispatch, inspect CPU and policy size |
| Cached identity verification p95 | < 5 ms | Inspect key cache and workload identity churn |
| Ordinary text inspection p95 | < 50 ms | Inspect input size, detector profile, and CPU |
| Policy activation / rollback | < 1 s | Retain last-known-good and abort rollout |
| Sidecar readiness | 99.99% per workload | Sensitive actions remain fail closed |
| Telemetry completeness | 100% enforcement receipts | Investigate degraded health immediately |

Canary rollouts must monitor attack-prevention and legitimate-utility traces.
Any configured regression threshold invokes the signed rollback path. A scanner
detection is not an enforcement success; dashboards count a blocked action only
when its receipt proves non-dispatch or a protected downstream rejects the
Guard token.
