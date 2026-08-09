import type { ChildProcess } from "node:child_process";

export interface GuardContext {
  eval_surface?: string;
  trace_stage?: string;
  policy_scope?: string;
  tool_name?: string;
  destination?: string;
  [key: string]: unknown;
}

export interface GuardOptions {
  bin?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  context?: GuardContext;
}

export interface ToolCallOptions extends GuardOptions {
  policyScope?: string;
}

export interface GuardVerdict {
  sanitized_text: string;
  suspicious: boolean;
  reasons: string[];
  confidence: number;
  scan_id?: string;
  model_version?: string;
  learning_version?: string;
  [key: string]: unknown;
}

export type ContentEffect =
  | "allow_trusted_instruction"
  | "allow_untrusted_data"
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
  trust: "platform" | "trusted" | "untrusted";
  data_classes: string[];
  instruction_authority: "system" | "developer" | "user" | "none";
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
    trust: ContentSegment["trust"];
    instruction_authority: ContentSegment["instruction_authority"];
    suspicious: boolean;
    reasons: string[];
  }>;
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
  action: { capability_id: string; operation_class: string; normalized_arguments: unknown };
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

export interface GuardPolicyDecision {
  schema_version: "armorer-guard-policy-decision/v1";
  request_id: string;
  policy_id: string;
  policy_revision: number;
  policy_digest: string;
  effect: "allow" | "deny" | "require_approval";
  decision_source: "fixed_invariant" | "adaptive" | "rule" | "default";
  matched_rule_ids: string[];
  reason_codes: string[];
  adaptive_tightening_applied: boolean;
  authority_expanded: false;
}

export interface McpProxyOptions extends GuardOptions {
  auditLog?: string;
  stdio?: "inherit" | "pipe" | "ignore";
}

export class ArmorerGuardError extends Error {
  code?: string | number;
  stderr?: string;
  stdout?: string;
  verdict?: GuardVerdict;
}
export class GuardApprovalRequiredError extends ArmorerGuardError { decision: any; }
export class GuardDeniedError extends ArmorerGuardError { decision: any; }
export class GuardSidecarClient {
  constructor(options?: {
    socketPath?: string;
    timeoutMs?: number;
    mtls?: { host: string; port: number; ca: string | Buffer; cert: string | Buffer; key: string | Buffer; servername?: string };
  });
  request(path: string, payload?: any, method?: string): Promise<any>;
  input(request: ContentEvaluationRequest): Promise<ContentDecision>;
  context(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelRequest(request: ContentEvaluationRequest): Promise<ContentDecision>;
  modelResponse(request: ContentEvaluationRequest): Promise<ContentDecision>;
  action(request: AuthorityRequest): Promise<any>;
  output(request: ContentEvaluationRequest): Promise<ContentDecision>;
  toolResult(request: ContentEvaluationRequest): Promise<ContentDecision>;
  memoryWrite(request: ContentEvaluationRequest): Promise<ContentDecision>;
  memoryRead(request: ContentEvaluationRequest): Promise<ContentDecision>;
  interAgent(request: ContentEvaluationRequest): Promise<ContentDecision>;
  capabilities(): Promise<any[]>;
  features(): Promise<Record<string, unknown>>;
  enforcementCoverage(): Promise<Record<string, unknown>>;
  operationalStatus(): Promise<Record<string, unknown>>;
  createApprovalChallenge(request: any): Promise<any>;
  consumeApproval(request: any): Promise<any>;
  authorizeExecution(request: any): Promise<any>;
  recordExecution(request: any): Promise<any>;
  accessEvidence(request: any): Promise<any>;
  brokerHttp(request: any): Promise<any>;
  brokerFilesystem(request: any): Promise<any>;
  replayTrace(request: any): Promise<any>;
}
export function canonicalJson(value: any): string;
export function canonicalDigest(value: any): string;
export function signCanonical(key: any, value: any): string;
export function protectCapability(client: GuardSidecarClient, options: {
  authorityRequest(input: any, run: any): any | Promise<any>;
  execute(input: any, token: any, run: any): any | Promise<any>;
}): (input: any, run?: any) => Promise<any>;
export function superviseModelCall(client: GuardSidecarClient, options: {
  requestEnvelope: any;
  invoke(requestDecision: any): any | Promise<any>;
  responseEnvelope(response: any, requestDecision: any): any | Promise<any>;
}): Promise<any>;
export function createOpenAICompatibleMiddleware(client: GuardSidecarClient): (options: any) => Promise<any>;
export function createOpenAIAgentsHooks(client: GuardSidecarClient): any;
export function createLangGraphHooks(client: GuardSidecarClient): any;
export function createCrewAIHooks(client: GuardSidecarClient): any;
export function createHttpWebhookGuard(client: GuardSidecarClient): any;

export function resolveArmorerGuardBin(options?: GuardOptions): string;
export function inspect(text: string, options?: GuardOptions): GuardVerdict;
export function inspectToolCall(
  toolName: string,
  args: unknown,
  options?: ToolCallOptions,
): GuardVerdict;
export function requireSafeToolArgs(
  toolName: string,
  args: unknown,
  options?: ToolCallOptions,
): GuardVerdict;
export function sanitize(text: string, options?: GuardOptions): Record<string, unknown>;
export function detectCredentials(text: string, options?: GuardOptions): Record<string, unknown> | null;
export function capabilities(options?: GuardOptions): Record<string, unknown>;
export function versionInfo(options?: GuardOptions): Record<string, unknown>;
export function evaluatePolicy(
  policyBundle: Record<string, unknown>,
  request: Record<string, unknown>,
  options?: GuardOptions,
): GuardPolicyDecision;
export function mcpProxyCommand(
  serverCommand: string,
  serverArgs?: string[],
  options?: McpProxyOptions,
): { command: string; args: string[] };
export function spawnMcpProxy(
  serverCommand: string,
  serverArgs?: string[],
  options?: McpProxyOptions,
): ChildProcess;
