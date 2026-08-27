import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";

import { GuardSidecarClient } from "@armorerlabs/guard";
import { ChatOpenAI } from "@langchain/openai";

import {
  GuardedLangGraphSupervisor,
  HmacAuthorityRequestFactory,
  type GuardRuntimeContext
} from "./guard-supervisor.js";
import {
  buildTicketAgent,
  TicketGateway,
  ticketCapabilities
} from "./ticket-agent.js";

function requiredEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required; do not invent a deployment value`);
  }
  return value;
}

function requiredRiskScore(): number {
  const value = Number(requiredEnvironment("ARMORER_LANGGRAPH_RISK_SCORE"));
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error("ARMORER_LANGGRAPH_RISK_SCORE must be between zero and one");
  }
  return value;
}

function requiredRetention(): GuardRuntimeContext["modelRoute"]["retention"] {
  const value = requiredEnvironment("ARMORER_LANGGRAPH_RETENTION");
  if (!(["none", "local_only", "provider_zero_retention"] as const).includes(
    value as GuardRuntimeContext["modelRoute"]["retention"]
  )) {
    throw new Error(
      "ARMORER_LANGGRAPH_RETENTION must be none, local_only, or provider_zero_retention"
    );
  }
  return value as GuardRuntimeContext["modelRoute"]["retention"];
}

function finalMessageText(result: { messages: Array<{ content: unknown }> }): string {
  const message = result.messages.at(-1);
  if (!message) throw new Error("LangGraph completed without a final message");
  if (typeof message.content === "string") return message.content;
  if (!Array.isArray(message.content)) {
    throw new Error("LangGraph final message used an unsupported content shape");
  }
  return message.content.map((part) => {
    if (typeof part === "string") return part;
    if (
      part !== null
      && typeof part === "object"
      && "text" in part
      && typeof part.text === "string"
    ) {
      return part.text;
    }
    throw new Error(
      "LangGraph final message contained a block this example cannot safely release"
    );
  }).join("\n");
}

function runtimeCapabilityIds(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new TypeError("Guard returned a non-array capability inventory");
  }
  return value.map((capability) => {
    if (
      capability === null
      || typeof capability !== "object"
      || !("id" in capability)
      || typeof capability.id !== "string"
      || capability.id.length === 0
    ) {
      throw new TypeError("Guard returned a capability without an exact ID");
    }
    return capability.id;
  });
}

function sameCapabilitySet(left: readonly string[], right: readonly string[]): boolean {
  return new Set(left).size === left.length
    && new Set(right).size === right.length
    && left.length === right.length
    && left.every((value) => right.includes(value));
}

async function main(): Promise<void> {
  const prompt = process.argv.slice(2).join(" ").trim();
  if (!prompt) {
    throw new Error('Pass a prompt, for example: npm start -- "Find the SSO ticket"');
  }
  requiredEnvironment("OPENAI_API_KEY");

  const modelRoute: GuardRuntimeContext["modelRoute"] = {
    provider: requiredEnvironment("ARMORER_LANGGRAPH_PROVIDER"),
    modelId: requiredEnvironment("ARMORER_LANGGRAPH_MODEL"),
    region: requiredEnvironment("ARMORER_LANGGRAPH_REGION"),
    retention: requiredRetention()
  };
  const modelOptions: ConstructorParameters<typeof ChatOpenAI>[0] = {
    model: modelRoute.modelId,
    temperature: 0
  };
  const baseURL = process.env.OPENAI_BASE_URL?.trim();
  if (baseURL) modelOptions.configuration = { baseURL };

  const delegationKey = await readFile(
    requiredEnvironment("ARMORER_GUARD_DELEGATION_KEY_FILE")
  );
  if (delegationKey.length < 32) {
    throw new Error("the Guard delegation key must contain at least 32 bytes");
  }

  const guard = new GuardSidecarClient({
    socketPath: requiredEnvironment("ARMORER_GUARD_SOCKET")
  });
  const gateway = new TicketGateway();
  const capabilities = ticketCapabilities(gateway);
  const adapterCapabilityIds = capabilities.map(
    (capability) => capability.capabilityId
  );
  const guardCapabilityIds = runtimeCapabilityIds(await guard.capabilities());
  if (!sameCapabilitySet(adapterCapabilityIds, guardCapabilityIds)) {
    throw new Error(
      `LangGraph adapter and Guard capability inventories differ: adapter=${adapterCapabilityIds.join(",")} guard=${guardCapabilityIds.join(",")}`
    );
  }

  const supervisor = new GuardedLangGraphSupervisor(
    guard,
    new HmacAuthorityRequestFactory(delegationKey),
    capabilities
  );
  const agent = buildTicketAgent({
    model: new ChatOpenAI(modelOptions),
    supervisor
  });
  const runId = randomUUID();
  const context: GuardRuntimeContext = {
    agentId: "langgraph-service-desk",
    workloadIdentity: "spiffe://example/agents/langgraph-service-desk",
    tenantId: "tenant/example-enterprise",
    principalId: "user/example-operator",
    delegatedBy: "user/example-operator",
    purpose: "enterprise-support",
    riskScore: requiredRiskScore(),
    traceId: `trace/${runId}`,
    sessionId: `session/${runId}`,
    dataClasses: ["internal"],
    modelRoute
  };

  const admittedInput = await supervisor.admitInput(prompt, context);
  const result = await agent.invoke(
    { messages: [{ role: "user", content: admittedInput }] },
    { context }
  );
  console.log(await supervisor.admitOutput(finalMessageText(result), context));
}

await main();
