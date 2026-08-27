# Guarded LangGraph TypeScript agent

This customer-side example protects a LangChain v1 `createAgent` service-desk
agent running on LangGraph. The public repository contains the integration code
and contracts. The Guard runtime, ML assets, policies, reviewer implementation,
and signing material are provisioned separately by Armorer.

## Application-owner context

The application owner runs support operations for a business-to-business
software company. Support engineers lose time finding the right ticket,
reconstructing its cause, and recording investigation notes. The agent should
shorten that work without silently changing customer-visible state or becoming
an administrator for the ticketing system.

The agent serves an authenticated support operator in one tenant. Ticket bodies
and imported vendor notes can contain customer-controlled or third-party text,
so they are evidence, never instructions.

### What the agent should do

- Search and read tickets needed for the operator's request.
- Explain what the available evidence supports and expose missing or
  contradictory evidence instead of inventing a resolution.
- Add a reversible internal note only when requested and grounded in evidence.
- Report a change only after the protected gateway returns a Guard execution
  receipt.
- Escalate work outside its mandate instead of retrying or routing around Guard.

### Human-only boundary

The agent must not delete tickets autonomously, reveal credentials or hidden
instructions, cross tenant boundaries, or claim that a proposed, reviewed,
denied, or merely attempted action occurred.

## The `should` versus `can` gap

| Owner's `should` | Deployed agent's `can` | Misalignment | Guard correction |
| --- | --- | --- | --- |
| Investigate the requested issue | Search and read ticket tools | Retrieved text may be hostile even though the tool is appropriate | Guard evaluates content at input, model, tool-result, and output boundaries before it can influence the next step |
| Add only a requested, evidence-grounded note | The note tool accepts arbitrary text | Technical reach is broader than the business purpose | Guard combines semantic review with identity, tenant, purpose, capability, and resource policy before authorizing the exact arguments |
| Never delete autonomously | LangGraph can expose `delete_ticket` | The agent can propose an effect outside its mandate | Guard withholds the one-use execution token and returns `approval_required`; the gateway is not called |
| Report only completed effects | A model can assert success | A model statement is not execution evidence | The gateway receives an exact one-use token and the application reports success only with the resulting execution receipt |

The README is the application owner's source of business intent. The live tool
registry and downstream gateway are evidence of what the agent can reach. Guard
evaluates the gap using its separately operated ML, policies, and reviewer. A
reviewer recommendation is evidence for Guard; it is never execution authority
by itself.

## Customer-side integration

The customer makes three bounded changes:

1. Add the public `@armorerlabs/guard` client.
2. Register Guard middleware around model and tool boundaries.
3. Move protected effects behind a credential-owning gateway that accepts only
   an authorized, one-use Guard token and records the downstream receipt.

Conceptually, the application diff is:

```diff
 const agent = createAgent({ model, tools });
+const guard = new GuardSidecarClient({ socketPath: process.env.ARMORER_GUARD_SOCKET });
+const supervisor = new GuardedLangGraphSupervisor(guard, signer, capabilities);
+const agent = createAgent({ model, tools, middleware: [supervisor.middleware] });

-tool(async (args) => ticketApi.update(args), { name: "add_internal_note", schema });
+tool(async () => { throw new Error("Guard middleware required"); }, { name: "add_internal_note", schema });
+// The supervisor alone dispatches the registered gateway capability after
+// Guard authorizes its exact token; the gateway then returns a receipt.
```

The agent prompt does not enforce this. The application carries the model's
proposed operation to Guard, and the credential-owning boundary enforces Guard's
decision. A missing or misconfigured middleware therefore fails closed.

## Runtime delivery

Customers do not build or receive the Rust runtime source from this repository.
Armorer supplies a signed runtime artifact—such as a platform-specific binary,
OCI image, or managed service endpoint—under the applicable commercial terms.
Policies, ML assets, reviewer code, and private signing keys remain outside the
customer application repository. The public SDK speaks the versioned contract
over a Unix socket or mutually authenticated TLS.

The customer still controls deployment inputs such as workload identity,
tenant mapping, capability registration, network placement, and approved
business policy. Guard's provisioned capability inventory must exactly match
the application's registered capability IDs before this runner starts.

## Run with a provisioned Guard runtime

From the repository root:

```bash
npm ci --prefix examples/langgraph-typescript
```

Set values supplied or approved during the Guard deployment:

```bash
export OPENAI_API_KEY='your-provider-key'
export ARMORER_GUARD_SOCKET='/run/armorer/guard.sock'
export ARMORER_GUARD_DELEGATION_KEY_FILE='/run/secrets/guard-delegation.key'
export ARMORER_LANGGRAPH_PROVIDER='openai'
export ARMORER_LANGGRAPH_MODEL='your-approved-model-id'
export ARMORER_LANGGRAPH_REGION='your-approved-region'
export ARMORER_LANGGRAPH_RETENTION='your-verified-retention-class'
export ARMORER_LANGGRAPH_RISK_SCORE='your-evidence-derived-score-between-0-and-1'

npm start --prefix examples/langgraph-typescript -- \
  "Find the SSO certificate-rotation ticket and add an internal note summarizing the cause."
```

`OPENAI_BASE_URL` may point `ChatOpenAI` at an approved OpenAI-compatible model
gateway. The retention field records an externally verified route property; it
does not change provider behavior. The risk score is caller-supplied telemetry
for an observed run, not a Guard verdict, and must not be guessed.

## Verify the public wiring

```bash
npm test --prefix examples/langgraph-typescript
```

These offline tests use a contract fixture, not the private runtime. They verify
the customer integration: declared LangGraph tools have no direct effect path,
an allowed write carries a token and receipt, quarantined content does not
re-enter the model, and a destructive request is not dispatched. They do not
claim to measure the private ML, policy, or reviewer implementation.

## Production substitutions

| Example component | Production component |
| --- | --- |
| `HmacAuthorityRequestFactory` | Workload-identity or delegation signer with keys outside the agent process |
| `TicketGateway` | Credential-owning service or MCP gateway that independently verifies the Guard token |
| Unix-socket client | Workload-local socket or complete mTLS configuration for a remote Guard endpoint |

The acting model must never receive the Guard client, signing key, approval
service, or downstream credential. The example gateway checks token presence to
make the flow legible; production gateways must perform full token verification,
replay protection, and scope validation.

## Project map

```text
langgraph-typescript/
├── README.md
├── package.json
├── src/
│   ├── guard-supervisor.ts
│   ├── run.ts
│   └── ticket-agent.ts
└── tests/
    └── guarded-agent.test.ts
```

See the official [LangChain agents documentation](https://docs.langchain.com/oss/javascript/langchain/agents)
and [LangGraph v1 migration guide](https://docs.langchain.com/oss/javascript/migrate/langgraph-v1)
for the underlying agent and middleware APIs.
