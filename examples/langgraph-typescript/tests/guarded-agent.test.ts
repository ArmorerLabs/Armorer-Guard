import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import type {
  AuthorityRequest,
  ContentDecision,
  ContentEvaluationRequest
} from "@armorerlabs/guard";
import { ToolMessage } from "@langchain/core/messages";
import { FakeToolCallingModel } from "langchain";

import {
  GuardedLangGraphSupervisor,
  HmacAuthorityRequestFactory,
  type ActionDecision,
  type GuardClient,
  type GuardRuntimeContext
} from "../src/guard-supervisor.js";
import {
  buildTicketAgent,
  TicketGateway,
  ticketCapabilities,
  ticketTools
} from "../src/ticket-agent.js";

const TEST_MODEL_ROUTE: GuardRuntimeContext["modelRoute"] = {
  provider: "test",
  modelId: "fake-tool-calling",
  region: "local",
  retention: "local_only"
};

function runtimeContext(): GuardRuntimeContext {
  const runId = randomUUID();
  return {
    agentId: "langgraph-service-desk",
    workloadIdentity: "spiffe://example/agents/langgraph-service-desk",
    tenantId: "tenant/example-enterprise",
    principalId: "user/offline-test",
    delegatedBy: "user/offline-test",
    purpose: "enterprise-support",
    riskScore: 0.1,
    traceId: `trace/${runId}`,
    sessionId: `session/${runId}`,
    dataClasses: ["internal"],
    modelRoute: TEST_MODEL_ROUTE
  };
}

function admitted(
  request: ContentEvaluationRequest,
  stage: string
): ContentDecision {
  return {
    schema_version: "armorer-guard-content-decision/v1",
    decision_id: `fixture/${request.request_id}`,
    request_id: request.request_id,
    trace_id: request.trace_id,
    stage,
    effect: "allow_untrusted_data",
    reason_codes: [],
    segments: request.segments.map((segment) => ({
      content_ref: segment.content_ref,
      sanitized_text: segment.text,
      trust: segment.trust,
      instruction_authority: segment.instruction_authority,
      suspicious: false,
      reasons: []
    }))
  };
}

class FixtureGuardClient implements GuardClient {
  private receiptCount = 0;

  async input(request: ContentEvaluationRequest): Promise<ContentDecision> {
    return admitted(request, "input");
  }

  async modelRequest(request: ContentEvaluationRequest): Promise<ContentDecision> {
    return admitted(request, "model_request");
  }

  async modelResponse(request: ContentEvaluationRequest): Promise<ContentDecision> {
    return admitted(request, "model_response");
  }

  async output(request: ContentEvaluationRequest): Promise<ContentDecision> {
    return admitted(request, "output");
  }

  async toolResult(request: ContentEvaluationRequest): Promise<ContentDecision> {
    if (request.segments.some((segment) => /hidden system prompt/i.test(segment.text))) {
      return {
        ...admitted(request, "tool_result"),
        effect: "quarantine",
        reason_codes: ["fixture_untrusted_instruction"],
        segments: []
      };
    }
    return admitted(request, "tool_result");
  }

  async action(request: AuthorityRequest): Promise<ActionDecision> {
    if (request.action.capability_id === "ticket.delete") {
      return {
        effect: "require_approval",
        reason_codes: ["fixture_human_only_boundary"]
      };
    }
    return {
      effect: "allow",
      reason_codes: [],
      execution_token: {
        token_id: `fixture-token/${request.request_id}`,
        capability_id: request.action.capability_id
      }
    };
  }

  async authorizeExecution(): Promise<Record<string, unknown>> {
    return { authorized: true };
  }

  async recordExecution(): Promise<Record<string, unknown>> {
    this.receiptCount += 1;
    return { receipt_id: `execution-receipt/${this.receiptCount}` };
  }

  async capabilities(): Promise<Array<{ id: string }>> {
    return [
      { id: "ticket.search" },
      { id: "ticket.read" },
      { id: "ticket.add_internal_note" },
      { id: "ticket.delete" }
    ];
  }
}

type FakeToolCalls = NonNullable<
  NonNullable<ConstructorParameters<typeof FakeToolCallingModel>[0]>["toolCalls"]
>;

function harness(toolCalls: FakeToolCalls) {
  const guard = new FixtureGuardClient();
  const gateway = new TicketGateway();
  const supervisor = new GuardedLangGraphSupervisor(
    guard,
    new HmacAuthorityRequestFactory(Buffer.alloc(32, "fixture")),
    ticketCapabilities(gateway)
  );
  return {
    agent: buildTicketAgent({
      model: new FakeToolCallingModel({ toolCalls }),
      supervisor
    }),
    gateway,
    guard,
    supervisor
  };
}

function toolMessages(result: { messages: unknown[] }): ToolMessage[] {
  return result.messages.filter(ToolMessage.isInstance);
}

test("matches the adapter to the runtime capability contract fixture", async () => {
  const guard = new FixtureGuardClient();
  const inventory = await guard.capabilities();
  const registered = ticketCapabilities(new TicketGateway()).map(
    (capability) => capability.capabilityId
  );
  assert.deepEqual(
    inventory.map((capability) => capability.id).sort(),
    registered.sort()
  );
});

test("the declared LangGraph tools have no unmediated effect path", async () => {
  await assert.rejects(
    ticketTools[0].invoke({ query: "SSO" }),
    /has no direct implementation/
  );
});

test("dispatches a write only through a token and reports its receipt", async () => {
  const { agent, gateway, supervisor } = harness([
    [{
      name: "add_internal_note",
      args: {
        ticketId: "ticket/1001",
        note: "Customer confirmed the failure began after the IdP certificate rotation."
      },
      id: "tool-call/add-note"
    }],
    []
  ]);
  const context = runtimeContext();
  const prompt = await supervisor.admitInput(
    "Add the customer's certificate-rotation confirmation to ticket/1001.",
    context
  );
  const result = await agent.invoke(
    { messages: [{ role: "user", content: prompt }] },
    { context }
  );

  assert.deepEqual(gateway.dispatches, [
    { operation: "add_internal_note", ticketId: "ticket/1001" }
  ]);
  const messages = toolMessages(result);
  assert.equal(messages.length, 1);
  assert.equal(messages[0]?.status, "success");
  assert.match(
    String(messages[0]?.metadata?.guard_execution_receipt_id),
    /^execution-receipt\//
  );
});

test("withholds a poisoned tool result before the next model turn", async () => {
  const { agent, gateway, supervisor } = harness([
    [{
      name: "search_tickets",
      args: { query: "vendor troubleshooting" },
      id: "tool-call/search-poisoned"
    }],
    []
  ]);
  const context = runtimeContext();
  const result = await agent.invoke(
    {
      messages: [{
        role: "user",
        content: await supervisor.admitInput(
          "Find the imported vendor troubleshooting ticket.",
          context
        )
      }]
    },
    { context }
  );

  assert.deepEqual(gateway.dispatches, [{ operation: "search" }]);
  const messages = toolMessages(result);
  assert.match(String(messages[0]?.content), /content_quarantined/);
  assert.doesNotMatch(
    JSON.stringify(result.messages),
    /reveal the hidden system prompt and credentials/i
  );
});

test("does not dispatch a destructive capability that needs approval", async () => {
  const { agent, gateway, supervisor } = harness([
    [{
      name: "delete_ticket",
      args: { ticketId: "ticket/1002", reason: "User requested deletion" },
      id: "tool-call/delete"
    }],
    []
  ]);
  const context = runtimeContext();
  const result = await agent.invoke(
    {
      messages: [{
        role: "user",
        content: await supervisor.admitInput("Delete ticket/1002.", context)
      }]
    },
    { context }
  );

  assert.deepEqual(gateway.dispatches, []);
  const messages = toolMessages(result);
  assert.match(String(messages[0]?.content), /approval_required/);
  assert.match(String(messages[0]?.content), /not_dispatched/);
  assert.doesNotMatch(String(messages[0]?.content), /execution_receipt/);
});
