# `@armorerlabs/guard`

Client-only Node SDK for an Armorer-provisioned Guard runtime. The package
contains transport, contracts, framework adapters, and fail-closed execution
helpers. It does not contain the Rust runtime, policies, models, reviewer, or
service credentials.

```js
import { GuardSidecarClient } from "@armorerlabs/guard";

const guard = new GuardSidecarClient({
  socketPath: process.env.ARMORER_GUARD_SOCKET,
});

const status = await guard.operationalStatus();
```

Protected effects still require a credential-owning gateway that independently
verifies the exact one-use execution token. Merely calling the SDK is not
enforcement proof. `protectCapability` returns both the downstream result and
the Guard execution receipt; keep that receipt attached to any success claim.

Generic model helpers fail closed if Guard transforms content because they
cannot safely reconstruct a provider-specific request or response. Use a
framework adapter that explicitly applies sanitized content when transformation
is required.

See the repository README and `examples/langgraph-typescript` for the complete
customer integration.
