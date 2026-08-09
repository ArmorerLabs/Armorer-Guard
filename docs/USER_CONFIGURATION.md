# Configure an agent with Armorer Guard

Guard is configured outside application source through a strict agent manifest.
The manifest binds one workload identity and tenant to approved model routes,
destinations, capabilities, approval roles, retention, adapters, and key files.
It contains paths to secrets, never the protected credentials themselves.

`protected_memory_keys` accepts exact names such as `agent.goal` or a single
trailing-wildcard prefix such as `identity.*`. An untrusted write to a matched
target is denied by the sidecar before the memory broker commits it.

Start from [`examples/agent-manifest.json`](../examples/agent-manifest.json),
replace its identities and absolute paths, then validate it:

```bash
armorer-guard validate --config /etc/armorer-guard/law-agent.json
armorer-guard explain --config /etc/armorer-guard/law-agent.json
armorer-guard explain \
  --config /etc/armorer-guard/law-agent.json \
  --capability case.delete
```

Validation fails on unknown fields, unsafe fail modes, duplicate capabilities,
cross-tenant destinations, unbounded retention, unknown approval targets, and
unmediated sensitive capabilities. `explain` returns the content-addressed
manifest digest and enforcement coverage inventory.

Run the sidecar:

```bash
armorer-guard serve \
  --config /etc/armorer-guard/law-agent.json \
  --data-dir /var/lib/armorer-guard/law-agent
```

The manifest's Unix socket is mode `0600`. At boot Guard validates the signed
policy and keys, registers the immutable capability inventory, and compiles the
model/destination allowlists. There is no agent-facing capability mutation API.

Windows uses the same HTTP contract over a local `\\.\pipe\...` named pipe.
Remote workloads set `transport.kind` to `mtls_tcp` and provide absolute paths
for the server certificate, server private key, and client CA. Python and
TypeScript clients require their own CA-signed client certificate and reject an
incomplete or unauthenticated remote configuration.

Raw retained evidence has no general read endpoint. `/v1/evidence/access`
requires a separate evidence-authorization key, an allowed reviewer role, exact
tenant/trace/content binding, purpose, and a short-lived signature. The access
itself emits metadata-only telemetry.

An agent uses the TypeScript or Python sidecar client to supervise ingress,
context, model requests and responses, tool-result re-entry, memory writes,
inter-agent messages, actions, and output. Protected tools follow this order:

```text
normalized authority request
  -> allow / deny / require_approval
  -> signed 30-second execution token on allow
  -> atomic single-use dispatch authorization
  -> protected operation
  -> execution receipt
```

The protected credential belongs in the gateway or broker, not the model or
agent process. A wrapper alone cannot prevent a direct call when the agent still
holds an unwrapped credential; such a route must be declared as an enforcement
frontier and is rejected for sensitive capabilities.

For a credential-owning HTTP broker, declare an HTTPS URL prefix, methods,
credential header, mode-`0600` credential file, and response limit in
`http_brokers`. The agent supplies only normalized URL/method/body arguments;
Guard rejects agent-controlled authorization headers and redirects. The broker
also injects the signed, hex-encoded execution token as
`X-Armorer-Guard-Execution-Token`, allowing the protected downstream to verify
the exact Guard authorization independently. A
filesystem broker declares an absolute root, operations, and byte limit in
`filesystem_brokers`; paths must be normalized and relative, and capability
filesystem access cannot follow a symlink outside the root.

For MCP, enable authority enforcement explicitly:

```bash
armorer-guard mcp-proxy \
  --sidecar-socket /run/armorer-guard/law-agent.sock \
  -- your-mcp-server
```

Each `tools/call` must include
`params._meta.armorer_guard.authority_request`. The proxy fails closed when it
is missing, consumes the execution token before forwarding, injects the token
for the protected MCP server, and reports the downstream result.
