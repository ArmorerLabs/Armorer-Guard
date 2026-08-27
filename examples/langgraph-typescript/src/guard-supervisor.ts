import { createHash } from "node:crypto";

import {
  type AIMessage,
  type BaseMessage,
  ToolMessage
} from "@langchain/core/messages";
import { createMiddleware } from "langchain";
import { z } from "zod";

import {
  signCanonical,
  type AuthorityRequest,
  type ContentDecision,
  type ContentEvaluationRequest
} from "@armorerlabs/guard";

const ADMITTED_CONTENT_EFFECTS = new Set([
  "allow",
  "allow_trusted_instruction",
  "allow_untrusted_data",
  "warn_and_allow",
  "redact_and_allow"
]);

export const guardRuntimeContextSchema = z.object({
  agentId: z.string().min(1),
  workloadIdentity: z.string().min(1),
  tenantId: z.string().min(1),
  principalId: z.string().min(1),
  delegatedBy: z.string().min(1),
  purpose: z.string().min(1),
  riskScore: z.number().min(0).max(1),
  traceId: z.string().min(1),
  sessionId: z.string().min(1),
  dataClasses: z.array(z.string().min(1)),
  modelRoute: z.object({
    provider: z.string().min(1),
    modelId: z.string().min(1),
    region: z.string().min(1),
    retention: z.enum(["none", "local_only", "provider_zero_retention"])
  })
});

export type GuardRuntimeContext = z.infer<typeof guardRuntimeContextSchema>;

export interface ActionDecision {
  effect: "allow" | "deny" | "require_approval";
  reason_codes: string[];
  execution_token?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GuardClient {
  input(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelRequest(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelResponse(request: ContentEvaluationRequest): Promise<ContentDecision>;
  action(request: AuthorityRequest): Promise<ActionDecision>;
  output(request: ContentEvaluationRequest): Promise<ContentDecision>;
  toolResult(request: ContentEvaluationRequest): Promise<ContentDecision>;
  authorizeExecution(request: Record<string, unknown>): Promise<Record<string, unknown>>;
  recordExecution(request: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export interface GuardedCapability {
  toolName: string;
  capabilityId: string;
  operationClass: "read" | "write" | "destructive" | "credential" | "external_send" | "code_execution";
  resourceType: string;
  resourceId(
    args: Readonly<Record<string, unknown>>,
    context: GuardRuntimeContext
  ): string;
  execute(
    args: Readonly<Record<string, unknown>>,
    executionToken: Readonly<Record<string, unknown>>,
    context: GuardRuntimeContext
  ): Promise<unknown>;
}

interface AuthorityRequestInput {
  capability: GuardedCapability;
  args: Readonly<Record<string, unknown>>;
  contentRefs: string[];
  context: GuardRuntimeContext;
  requestId: string;
}

export interface AuthorityRequestFactory {
  create(input: AuthorityRequestInput): Promise<AuthorityRequest> | AuthorityRequest;
}

export class GuardBoundaryError extends Error {
  constructor(
    message: string,
    readonly decision?: unknown
  ) {
    super(message);
    this.name = "GuardBoundaryError";
  }
}

export class HmacAuthorityRequestFactory implements AuthorityRequestFactory {
  constructor(
    private readonly signingKey: Buffer,
    private readonly now: () => number = () => Math.floor(Date.now() / 1_000)
  ) {}

  create(input: AuthorityRequestInput): AuthorityRequest {
    const observedAt = this.now();
    const request: AuthorityRequest = {
      schema_version: "armorer-guard-authority-request/v2",
      request_id: input.requestId,
      subject: {
        agent_id: input.context.agentId,
        workload_identity: input.context.workloadIdentity,
        tenant_id: input.context.tenantId
      },
      delegation: {
        delegated_by: input.context.delegatedBy,
        capability_ids: [input.capability.capabilityId],
        purpose: input.context.purpose,
        depth: 1,
        expires_at: observedAt + 300,
        signature: ""
      },
      action: {
        capability_id: input.capability.capabilityId,
        operation_class: input.capability.operationClass,
        normalized_arguments: input.args
      },
      resource: {
        resource_type: input.capability.resourceType,
        resource_id: input.capability.resourceId(input.args, input.context),
        tenant_id: input.context.tenantId,
        data_classes: input.context.dataClasses
      },
      influence: {
        content_refs: input.contentRefs,
        contains_untrusted_content: input.contentRefs.length > 0
      },
      context: {
        trace_id: input.context.traceId,
        session_id: input.context.sessionId,
        risk_score: input.context.riskScore,
        observed_at: observedAt,
        approval_receipts: []
      }
    };
    const signingPayload = {
      request_id: request.request_id,
      subject: request.subject,
      delegation: {
        delegated_by: request.delegation.delegated_by,
        capability_ids: request.delegation.capability_ids,
        purpose: request.delegation.purpose,
        depth: request.delegation.depth,
        expires_at: request.delegation.expires_at
      },
      action: request.action,
      resource: request.resource,
      influence: request.influence,
      context: {
        trace_id: request.context.trace_id,
        session_id: request.context.session_id,
        risk_score: request.context.risk_score
      }
    };
    request.delegation.signature = signCanonical(this.signingKey, signingPayload);
    return request;
  }
}

function contentRef(text: string): `content/sha256:${string}` {
  return `content/sha256:${createHash("sha256").update(text).digest("hex")}`;
}

function messageContentText(content: BaseMessage["content"]): string {
  if (typeof content === "string") {
    return content;
  }
  return content
    .map((part) => {
      if (typeof part === "string") {
        return part;
      }
      if ("text" in part && typeof part.text === "string") {
        return part.text;
      }
      return JSON.stringify(part);
    })
    .join("\n");
}

function modelResponseText(message: AIMessage): string {
  return JSON.stringify({
    content: messageContentText(message.content),
    tool_calls: message.tool_calls ?? []
  });
}

function requireAdmittedSegment(
  decision: ContentDecision,
  boundary: string
): ContentDecision["segments"][number] {
  const segment = decision.segments[0];
  if (!ADMITTED_CONTENT_EFFECTS.has(decision.effect) || !segment) {
    throw new GuardBoundaryError(
      `Armorer Guard withheld ${boundary}: ${decision.effect}`,
      decision
    );
  }
  return segment;
}

function requiredToolCallId(value: string | undefined): string {
  if (!value) {
    throw new GuardBoundaryError(
      "LangGraph produced a tool call without the ID required for a guarded result"
    );
  }
  return value;
}

function denialMessage(
  toolCallId: string,
  decision: ActionDecision
): ToolMessage {
  return new ToolMessage({
    tool_call_id: toolCallId,
    status: "error",
    content: JSON.stringify({
      status:
        decision.effect === "require_approval"
          ? "approval_required"
          : "guard_denied",
      effect: "not_dispatched",
      guard_effect: decision.effect
    }),
    metadata: {
      guard_reason_codes: decision.reason_codes
    }
  });
}

/**
 * Bind a LangChain v1 agent (running on LangGraph) to Guard's content and
 * authority contracts. Tool declarations never hold the protected operation;
 * this middleware dispatches only the exact capability registered below.
 */
export class GuardedLangGraphSupervisor {
  readonly middleware;

  private requestCount = 0;
  private readonly capabilities = new Map<string, GuardedCapability>();
  private readonly contentRefsBySession = new Map<string, Set<string>>();

  constructor(
    private readonly guard: GuardClient,
    private readonly authorityRequests: AuthorityRequestFactory,
    capabilities: readonly GuardedCapability[],
    private readonly now: () => number = () => Math.floor(Date.now() / 1_000)
  ) {
    for (const capability of capabilities) {
      if (this.capabilities.has(capability.toolName)) {
        throw new TypeError(`duplicate guarded tool ${capability.toolName}`);
      }
      this.capabilities.set(capability.toolName, capability);
    }

    this.middleware = createMiddleware({
      name: "ArmorerGuardMiddleware",
      contextSchema: guardRuntimeContextSchema,
      wrapModelCall: async (request, handler) => {
        const context = request.runtime.context;
        const modelRequest = this.modelContextRequest(
          request.systemMessage,
          request.messages,
          context
        );
        const requestDecision = await this.guard.modelRequest(
          modelRequest
        );
        this.requireExactStructuredAdmission(
          requestDecision,
          modelRequest,
          context.sessionId,
          "LangGraph model request"
        );

        const response = await handler(request);
        const serializedResponse = modelResponseText(response);
        const responseDecision = await this.guard.modelResponse(
          this.contentRequest({
            text: serializedResponse,
            origin: "langgraph_model_response",
            principalId: this.modelPrincipal(context),
            context
          })
        );
        const admittedResponse = requireAdmittedSegment(
          responseDecision,
          "LangGraph model response"
        );
        if (admittedResponse.sanitized_text !== serializedResponse) {
          throw new GuardBoundaryError(
            "Guard transformed a structured model response that this adapter cannot safely reconstruct",
            responseDecision
          );
        }
        this.rememberContentRef(context.sessionId, admittedResponse.content_ref);
        return response;
      },
      wrapToolCall: async (request, _handler) => {
        const context = request.runtime.context;
        const toolCallId = requiredToolCallId(request.toolCall.id);
        const capability = this.capabilities.get(request.toolCall.name);
        if (!capability) {
          throw new GuardBoundaryError(
            `No Guard capability is registered for LangGraph tool ${request.toolCall.name}`
          );
        }
        const authorityRequest = await this.authorityRequests.create({
          capability,
          args: request.toolCall.args,
          contentRefs: this.sessionContentRefs(context.sessionId),
          context,
          requestId: this.nextRequestId(context, request.toolCall.name)
        });
        const decision = await this.guard.action(authorityRequest);
        if (decision.effect !== "allow" || !decision.execution_token) {
          return denialMessage(toolCallId, decision);
        }

        const token = decision.execution_token;
        const grant = await this.guard.authorizeExecution({
          schema_version: "armorer-guard-execution-dispatch/v1",
          token,
          observed_at: this.now()
        });
        if (grant.authorized !== true) {
          throw new GuardBoundaryError(
            "Guard did not authorize the exact one-use execution token",
            grant
          );
        }

        let result: unknown;
        try {
          // Intentionally do not call LangGraph's unguarded tool handler. The
          // registered capability is the only implementation that can reach the
          // protected gateway, and it receives the exact Guard token.
          result = await capability.execute(request.toolCall.args, token, context);
        } catch (executionError) {
          try {
            await this.recordExecution(token, "failed");
          } catch (receiptError) {
            throw new AggregateError(
              [executionError, receiptError],
              "Tool execution failed and its Guard receipt could not be recorded"
            );
          }
          throw executionError;
        }
        const executionReceipt = await this.recordExecution(token, "succeeded");

        const serializedResult = JSON.stringify(result);
        if (typeof serializedResult !== "string") {
          throw new GuardBoundaryError(
            `${request.toolCall.name} returned a result that cannot be bound as JSON`
          );
        }
        const contentDecision = await this.guard.toolResult(
          this.contentRequest({
            text: serializedResult,
            origin: `langgraph_tool_result/${request.toolCall.name}`,
            principalId: `tool/${request.toolCall.name}`,
            context
          })
        );
        if (!ADMITTED_CONTENT_EFFECTS.has(contentDecision.effect)) {
          return new ToolMessage({
            tool_call_id: toolCallId,
            status: "error",
            content: JSON.stringify({
              status: "content_quarantined",
              effect: contentDecision.effect
            }),
            metadata: {
              guard_reason_codes: contentDecision.reason_codes,
              guard_execution_receipt_id: executionReceipt.receipt_id
            }
          });
        }
        const admittedResult = requireAdmittedSegment(
          contentDecision,
          `result from ${request.toolCall.name}`
        );
        this.rememberContentRef(context.sessionId, admittedResult.content_ref);
        return new ToolMessage({
          tool_call_id: toolCallId,
          status: "success",
          content: admittedResult.sanitized_text,
          metadata: {
            guard_execution_receipt_id: executionReceipt.receipt_id
          }
        });
      }
    });
  }

  async admitInput(
    text: string,
    context: GuardRuntimeContext
  ): Promise<string> {
    const decision = await this.guard.input(
      this.contentRequest({
        text,
        origin: "user_message",
        principalId: context.principalId,
        context
      })
    );
    const segment = requireAdmittedSegment(decision, "user input");
    this.rememberContentRef(context.sessionId, segment.content_ref);
    return segment.sanitized_text;
  }

  async admitOutput(
    text: string,
    context: GuardRuntimeContext
  ): Promise<string> {
    const decision = await this.guard.output(
      this.contentRequest({
        text,
        origin: "model_output",
        principalId: this.modelPrincipal(context),
        context
      })
    );
    return requireAdmittedSegment(decision, "final agent output").sanitized_text;
  }

  private contentRequest(input: {
    text: string;
    origin: string;
    principalId: string;
    context: GuardRuntimeContext;
  }): ContentEvaluationRequest {
    return {
      schema_version: "armorer-guard-content-evaluation/v1",
      request_id: this.nextRequestId(input.context, input.origin),
      trace_id: input.context.traceId,
      session_id: input.context.sessionId,
      purpose: input.context.purpose,
      subject: {
        agent_id: input.context.agentId,
        identity_id: input.context.workloadIdentity,
        tenant_id: input.context.tenantId
      },
      segments: [
        this.contentSegment({
          text: input.text,
          origin: input.origin,
          principalId: input.principalId,
          context: input.context,
          trust: "untrusted",
          instructionAuthority: "none"
        })
      ]
    };
  }

  private modelContextRequest(
    systemMessage: BaseMessage,
    messages: BaseMessage[],
    context: GuardRuntimeContext
  ): ContentEvaluationRequest {
    const segments: ContentEvaluationRequest["segments"] = [];
    const systemText = messageContentText(systemMessage.content);
    if (systemText.length > 0) {
      segments.push(
        this.contentSegment({
          text: systemText,
          origin: "langgraph_system_prompt",
          principalId: `host/${context.agentId}`,
          context,
          trust: "platform",
          instructionAuthority: "system"
        })
      );
    }
    for (const [index, message] of messages.entries()) {
      const text = messageContentText(message.content);
      if (text.length === 0) {
        continue;
      }
      segments.push(
        this.contentSegment({
          text,
          origin: `langgraph_${message.getType()}_message/${index}`,
          principalId: this.messagePrincipal(message, context),
          context,
          trust: "untrusted",
          instructionAuthority: "none"
        })
      );
    }
    if (segments.length === 0) {
      throw new GuardBoundaryError(
        "LangGraph model request contained no text that Guard could bind"
      );
    }
    return {
      schema_version: "armorer-guard-content-evaluation/v1",
      request_id: this.nextRequestId(context, "langgraph_model_context"),
      trace_id: context.traceId,
      session_id: context.sessionId,
      purpose: context.purpose,
      subject: {
        agent_id: context.agentId,
        identity_id: context.workloadIdentity,
        tenant_id: context.tenantId
      },
      model_route: {
        provider: context.modelRoute.provider,
        model_id: context.modelRoute.modelId,
        region: context.modelRoute.region,
        retention: context.modelRoute.retention,
        allowed_data_classes: context.dataClasses
      },
      segments
    };
  }

  private contentSegment(input: {
    text: string;
    origin: string;
    principalId: string;
    context: GuardRuntimeContext;
    trust: "platform" | "trusted" | "untrusted";
    instructionAuthority: "system" | "developer" | "user" | "none";
  }): ContentEvaluationRequest["segments"][number] {
    return {
      content_ref: contentRef(input.text),
      origin: input.origin,
      principal_id: input.principalId,
      tenant_id: input.context.tenantId,
      trust: input.trust,
      data_classes: input.context.dataClasses,
      instruction_authority: input.instructionAuthority,
      retention: "local_only",
      text: input.text
    };
  }

  private messagePrincipal(
    message: BaseMessage,
    context: GuardRuntimeContext
  ): string {
    switch (message.getType()) {
      case "human":
        return context.principalId;
      case "ai":
        return this.modelPrincipal(context);
      case "tool":
      case "function":
        return `tool/${message.name ?? "unnamed"}`;
      case "system":
        return `host/${context.agentId}`;
      default:
        throw new GuardBoundaryError(
          `LangGraph produced an unsupported message type ${message.getType()}`
        );
    }
  }

  private modelPrincipal(context: GuardRuntimeContext): string {
    return `model/${context.modelRoute.provider}/${context.modelRoute.modelId}`;
  }

  private requireExactStructuredAdmission(
    decision: ContentDecision,
    request: ContentEvaluationRequest,
    sessionId: string,
    boundary: string
  ): void {
    if (!ADMITTED_CONTENT_EFFECTS.has(decision.effect)) {
      throw new GuardBoundaryError(
        `Armorer Guard withheld ${boundary}: ${decision.effect}`,
        decision
      );
    }
    const requestText = new Map<string, string>(
      request.segments.map((segment) => [segment.content_ref, segment.text])
    );
    if (decision.segments.length !== requestText.size) {
      throw new GuardBoundaryError(
        `Guard returned an incomplete decision for ${boundary}`,
        decision
      );
    }
    const decidedRefs = new Set<string>();
    for (const segment of decision.segments) {
      const original = requestText.get(segment.content_ref);
      if (
        original === undefined
        || decidedRefs.has(segment.content_ref)
        || segment.sanitized_text !== original
      ) {
        throw new GuardBoundaryError(
          `Guard transformed structured ${boundary} content that this adapter cannot safely reconstruct`,
          decision
        );
      }
      decidedRefs.add(segment.content_ref);
      this.rememberContentRef(sessionId, segment.content_ref);
    }
  }

  private nextRequestId(context: GuardRuntimeContext, operation: string): string {
    this.requestCount += 1;
    const normalizedOperation = operation.replaceAll(/[^a-zA-Z0-9._/-]/g, "-");
    return `${context.traceId}/${normalizedOperation}/${this.requestCount}`;
  }

  private rememberContentRef(sessionId: string, value: string): void {
    const refs = this.contentRefsBySession.get(sessionId) ?? new Set<string>();
    refs.add(value);
    this.contentRefsBySession.set(sessionId, refs);
  }

  private sessionContentRefs(sessionId: string): string[] {
    return [...(this.contentRefsBySession.get(sessionId) ?? [])];
  }

  private recordExecution(
    token: Readonly<Record<string, unknown>>,
    outcome: "succeeded" | "failed"
  ): Promise<Record<string, unknown>> {
    return this.guard.recordExecution({
      schema_version: "armorer-guard-execution-report/v1",
      token,
      downstream_dispatched: true,
      downstream_outcome: outcome,
      observed_at: this.now()
    });
  }
}
