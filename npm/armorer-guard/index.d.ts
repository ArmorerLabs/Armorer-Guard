import type { BinaryLike, KeyObject } from "node:crypto";

export type TrustClass = "platform" | "trusted" | "untrusted";
export type InstructionAuthority = "system" | "developer" | "user" | "none";
export type ContentEffect =
  | "allow"
  | "allow_trusted_instruction"
  | "allow_untrusted_data"
  | "warn_and_allow"
  | "redact_and_allow"
  | "quarantine"
  | "require_approval"
  | "deny";

export interface RuntimeSubject {
  agent_id: string;
  identity_id: string;
  tenant_id: string;
}

export interface ContentSegment {
  content_ref: `content/sha256:${string}`;
  origin: string;
  principal_id: string;
  tenant_id: string;
  trust: TrustClass;
  data_classes: string[];
  instruction_authority: InstructionAuthority;
  retention: string;
  influenced_by?: string[];
  text: string;
}

export interface ContentEvaluationRequest {
  schema_version: "armorer-guard-content-evaluation/v1";
  request_id: string;
  trace_id: string;
  session_id: string;
  subject: RuntimeSubject;
  purpose?: string | null;
  allowed_context_origins?: string[];
  model_route?: {
    provider: string;
    model_id: string;
    region: string;
    retention: string;
    allowed_data_classes?: string[];
  } | null;
  segments: ContentSegment[];
  destination?: {
    destination_id: string;
    tenant_id: string;
    destination_type: string;
    approved: boolean;
    allowed_data_classes?: string[];
  } | null;
  memory_target?: { namespace: string; key: string } | null;
}

export interface ContentFinding {
  reason_code: string;
  lane: string;
  category: string;
  confidence: number;
  disposition: "observe" | "review" | "block";
}

export interface ContentDecision {
  schema_version: "armorer-guard-content-decision/v1";
  decision_id: string;
  request_id: string;
  trace_id: string;
  stage: string;
  effect: ContentEffect;
  reason_codes: string[];
  segments: Array<{
    content_ref: string;
    sanitized_text: string;
    trust: TrustClass;
    instruction_authority: InstructionAuthority;
    disposition?: "observe" | "review" | "block";
    suspicious: boolean;
    reasons: string[];
    findings?: ContentFinding[];
  }>;
  content_review?: Record<string, unknown>;
}

export interface AuthorityRequest {
  schema_version: "armorer-guard-authority-request/v2";
  request_id: string;
  subject: { agent_id: string; workload_identity: string; tenant_id: string };
  delegation: {
    delegated_by: string;
    capability_ids: string[];
    purpose: string;
    depth: number;
    expires_at: number;
    signature: string;
  };
  action: {
    capability_id: string;
    operation_class: string;
    normalized_arguments: unknown;
  };
  resource: {
    resource_type: string;
    resource_id: string;
    tenant_id: string;
    data_classes: string[];
  };
  influence: { content_refs: string[]; contains_untrusted_content: boolean };
  context: {
    trace_id: string;
    session_id: string;
    risk_score: number;
    observed_at: number;
    approval_receipts: string[];
  };
}

export interface ActionDecision {
  effect: "allow" | "deny" | "require_approval";
  reason_codes: string[];
  execution_token?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GuardClientOptions {
  socketPath?: string;
  timeoutMs?: number;
  maxBodyBytes?: number;
  mtls?: {
    host: string;
    port: number;
    ca: string | Buffer;
    cert: string | Buffer;
    key: string | Buffer;
    servername?: string;
  };
}

export class ArmorerGuardError extends Error {
  code?: string | number;
  decision?: unknown;
}
export class GuardApprovalRequiredError extends ArmorerGuardError {
  decision: ActionDecision;
}
export class GuardDeniedError extends ArmorerGuardError {
  decision: ActionDecision;
}

export class GuardSidecarClient {
  constructor(options?: GuardClientOptions);
  request(path: string, payload?: unknown, method?: "GET" | "POST"): Promise<any>;
  input(request: ContentEvaluationRequest): Promise<ContentDecision>;
  context(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelRequest(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelResponse(request: ContentEvaluationRequest): Promise<ContentDecision>;
  action(request: AuthorityRequest): Promise<ActionDecision>;
  output(request: ContentEvaluationRequest): Promise<ContentDecision>;
  toolResult(request: ContentEvaluationRequest): Promise<ContentDecision>;
  memoryWrite(request: ContentEvaluationRequest): Promise<ContentDecision>;
  memoryRead(request: ContentEvaluationRequest): Promise<ContentDecision>;
  interAgent(request: ContentEvaluationRequest): Promise<ContentDecision>;
  capabilities(): Promise<Array<{ id: string; [key: string]: unknown }>>;
  features(): Promise<Record<string, unknown>>;
  enforcementCoverage(): Promise<Record<string, unknown>>;
  operationalStatus(): Promise<Record<string, unknown>>;
  createApprovalChallenge(request: unknown): Promise<Record<string, unknown>>;
  consumeApproval(request: unknown): Promise<Record<string, unknown>>;
  authorizeExecution(request: unknown): Promise<Record<string, unknown>>;
  recordExecution(request: unknown): Promise<Record<string, unknown>>;
}

export function canonicalJson(value: unknown): string;
export function canonicalDigest(value: unknown): `sha256:${string}`;
export function signCanonical(key: BinaryLike | KeyObject, value: unknown): `hmac-sha256:${string}`;
export interface GuardedExecution<TResult> {
  result: TResult;
  executionReceipt: Record<string, unknown>;
}
export function protectCapability<TInput, TResult>(
  client: GuardSidecarClient,
  options: {
    authorityRequest(input: TInput, run: unknown): AuthorityRequest | Promise<AuthorityRequest>;
    execute(input: TInput, token: Record<string, unknown>, run: unknown): TResult | Promise<TResult>;
  },
): (input: TInput, run?: unknown) => Promise<GuardedExecution<TResult>>;
export function superviseModelCall(client: GuardSidecarClient, options: {
  requestEnvelope: ContentEvaluationRequest;
  invoke(requestDecision: ContentDecision): unknown | Promise<unknown>;
  responseEnvelope(response: unknown, requestDecision: ContentDecision): ContentEvaluationRequest | Promise<ContentEvaluationRequest>;
}): Promise<{ response: unknown; guard: { request: ContentDecision; response: ContentDecision } }>;
export function createOpenAICompatibleMiddleware(client: GuardSidecarClient): (options: unknown) => Promise<unknown>;
export function createOpenAIAgentsHooks(client: GuardSidecarClient): Record<string, unknown>;
export function createLangGraphHooks(client: GuardSidecarClient): Record<string, unknown>;
export function createCrewAIHooks(client: GuardSidecarClient): Record<string, unknown>;
export function createHttpWebhookGuard(client: GuardSidecarClient): Record<string, unknown>;
