<div align="center">

# Armorer Guard SDK

### Public integration contracts for an Armorer-provisioned Guard runtime

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-22.19%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/SDK_license-MIT-blue)](LICENSE.md)

</div>

This repository is the customer-side integration surface for Armorer Guard. It
contains dependency-light Python and Node/TypeScript clients, versioned wire
contracts, framework adapters, tests, and an enterprise LangGraph example.

It does **not** contain the Guard runtime, Rust source, policies, ML assets,
reviewer implementation, proprietary evaluation data, or production signing
material. Armorer distributes the runtime separately as a signed binary, OCI
image, or managed service under the applicable commercial agreement.

## What customers change

Guard is placed at the application's model and effect boundaries:

```text
application owner mandate
          |
          v
agent proposes model/tool work
          |
          v
public SDK -> provisioned Guard runtime -> deny / approval / one-use token
                                             |
                                             v
                              credential-owning protected gateway
                                             |
                                             v
                                      execution receipt
```

The customer:

1. installs the public client;
2. supplies workload, tenant, purpose, resource, and content provenance in the
   versioned request envelopes;
3. wraps model traffic and protected tool calls with framework middleware;
4. removes any direct credential path from the acting agent to the protected
   downstream; and
5. reports an effect only after Guard authorizes the exact one-use token and a
   downstream execution receipt is recorded.

Guard's value is not another system prompt. The application owner defines what
the agent should do; the deployed tool and credential boundaries show what it
can do. The separately operated Guard runtime uses ML, policy, and bounded
review to evaluate that misalignment. Policy or reviewer output alone does not
execute an action.

## Install the current v1 clients

The v1 source is on `main`, but publishing it to npm and PyPI is a separate
release operation. Until an explicit v1 registry release is completed, clone
this repository and install the clients from that checkout. The older versions
currently available from the registries belong to the earlier runtime-bundled
release line.

```bash
git clone https://github.com/ArmorerLabs/Armorer-Guard.git
```

Node/TypeScript:

```bash
npm install /path/to/Armorer-Guard/npm/armorer-guard
```

```ts
import { GuardSidecarClient } from "@armorerlabs/guard";

const guard = new GuardSidecarClient({
  socketPath: process.env.ARMORER_GUARD_SOCKET
});
const inventory = await guard.capabilities();
```

Python:

```bash
python -m pip install /path/to/Armorer-Guard
```

```python
from armorer_guard import GuardSidecar

guard = GuardSidecar(socket_path="/run/armorer/guard.sock")
inventory = guard.capabilities()
```

Both clients support a local Unix socket. They also support a remote endpoint
only with a complete mutually authenticated TLS identity. They fail closed on
transport errors, invalid responses, incomplete authorization, and missing
execution receipts.

## Enterprise TypeScript example

[`examples/langgraph-typescript`](examples/langgraph-typescript) starts with the
application owner's business context and shows a LangGraph service-desk agent
whose technical ticket capabilities exceed its autonomous mandate. It shows the
customer diff, Guard middleware, capability parity check, protected gateway,
one-use token, and receipt path without embedding the private runtime or a
plaintext policy.

The example's offline tests use contract fixtures. They prove SDK wiring, not
the behavior or performance of the private runtime.

## Repository boundary

```text
.
├── armorer_guard/                 # Python client and adapters
├── npm/armorer-guard/             # Node/TypeScript client
├── schemas/                       # public wire contracts
├── examples/langgraph-typescript/ # customer integration example
└── tests/                         # public client tests
```

The MIT license in this repository covers only the files present here. It does
not grant rights to separately delivered Guard runtime artifacts or services.
Previously published repository versions remain governed by the license that
accompanied those versions.

Version 1.0 is intentionally client-only. The earlier bundled CLI/runtime APIs
are not part of this package surface; deployments connect to a separately
provisioned runtime endpoint instead.

## Verify

```bash
python -m pytest -q
npm test --prefix npm/armorer-guard
npm ci --prefix examples/langgraph-typescript
npm test --prefix examples/langgraph-typescript
```

## Security

Report suspected vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). Do not include customer prompts, credentials,
tokens, policies, or runtime artifacts in public issues.
