use serde::{Deserialize, Serialize};

pub const CONTENT_REQUEST_VERSION: &str = "armorer-guard-content-evaluation/v1";
pub const CONTENT_DECISION_VERSION: &str = "armorer-guard-content-decision/v1";
pub const AUTHORITY_REQUEST_VERSION: &str = "armorer-guard-authority-request/v2";
pub const AUTHORITY_DECISION_VERSION: &str = "armorer-guard-authority-decision/v2";
pub const EVENT_VERSION: &str = "armorer-guard-event/v1";
pub const EXECUTION_RECEIPT_VERSION: &str = "armorer-guard-execution-receipt/v1";
pub const POLICY_MUTATION_VERSION: &str = "armorer-guard-policy-mutation/v1";
pub const POLICY_SIMULATION_VERSION: &str = "armorer-guard-policy-simulation/v1";
pub const ROLLOUT_OBSERVATION_VERSION: &str = "armorer-guard-rollout-observation/v1";
pub const TELEMETRY_QUERY_VERSION: &str = "armorer-guard-telemetry-query/v1";
pub const EVIDENCE_ACCESS_VERSION: &str = "armorer-guard-evidence-access/v1";
pub const REPLAY_QUERY_VERSION: &str = "armorer-guard-replay-query/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubject {
    pub agent_id: String,
    pub identity_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    Platform,
    Trusted,
    Untrusted,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstructionAuthority {
    System,
    Developer,
    User,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentSegment {
    pub content_ref: String,
    pub origin: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub trust: TrustClass,
    pub data_classes: Vec<String>,
    pub instruction_authority: InstructionAuthority,
    pub retention: String,
    #[serde(default)]
    pub influenced_by: Vec<String>,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDestination {
    pub destination_id: String,
    pub tenant_id: String,
    pub destination_type: String,
    pub approved: bool,
    #[serde(default)]
    pub allowed_data_classes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRouteRequest {
    pub provider: String,
    pub model_id: String,
    pub region: String,
    pub retention: String,
    #[serde(default)]
    pub allowed_data_classes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryWriteTarget {
    pub namespace: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentEvaluationRequest {
    pub schema_version: String,
    pub request_id: String,
    pub trace_id: String,
    pub session_id: String,
    pub subject: RuntimeSubject,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub allowed_context_origins: Vec<String>,
    #[serde(default)]
    pub model_route: Option<ModelRouteRequest>,
    pub segments: Vec<ContentSegment>,
    #[serde(default)]
    pub destination: Option<ContentDestination>,
    #[serde(default)]
    pub memory_target: Option<MemoryWriteTarget>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentEffect {
    AllowTrustedInstruction,
    AllowUntrustedData,
    RedactAndAllow,
    Quarantine,
    RequireApproval,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluatedSegment {
    pub content_ref: String,
    pub sanitized_text: String,
    pub trust: TrustClass,
    pub instruction_authority: InstructionAuthority,
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentDecision {
    pub schema_version: &'static str,
    pub decision_id: String,
    pub request_id: String,
    pub trace_id: String,
    pub stage: String,
    pub effect: ContentEffect,
    pub reason_codes: Vec<String>,
    pub segments: Vec<EvaluatedSegment>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySubjectV2 {
    pub agent_id: String,
    pub workload_identity: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDelegationV2 {
    pub delegated_by: String,
    pub capability_ids: Vec<String>,
    pub purpose: String,
    pub depth: u32,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityActionV2 {
    pub capability_id: String,
    pub operation_class: String,
    #[serde(default)]
    pub normalized_arguments: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityResourceV2 {
    pub resource_type: String,
    pub resource_id: String,
    pub tenant_id: String,
    pub data_classes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInfluenceV2 {
    pub content_refs: Vec<String>,
    pub contains_untrusted_content: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContextV2 {
    pub trace_id: String,
    pub session_id: String,
    pub risk_score: f64,
    pub observed_at: u64,
    pub approval_receipts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequestV2 {
    pub schema_version: String,
    pub request_id: String,
    pub subject: AuthoritySubjectV2,
    pub delegation: AuthorityDelegationV2,
    pub action: AuthorityActionV2,
    pub resource: AuthorityResourceV2,
    pub influence: AuthorityInfluenceV2,
    pub context: AuthorityContextV2,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorityDecisionV2 {
    pub schema_version: &'static str,
    pub decision_id: String,
    pub request_id: String,
    pub trace_id: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub effect: crate::policy::PolicyEffect,
    pub decision_source: String,
    pub matched_rule_ids: Vec<String>,
    pub reason_codes: Vec<String>,
    pub adaptive_tightening_applied: bool,
    pub authority_expanded: bool,
    pub execution_token: Option<super::enforcement::ExecutionToken>,
    pub execution_receipt: Option<ExecutionReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutionReceipt {
    pub schema_version: &'static str,
    pub receipt_id: String,
    pub decision_id: String,
    pub execution_token_id: Option<String>,
    pub capability_id: String,
    pub effect: crate::policy::PolicyEffect,
    pub downstream_dispatched: bool,
    pub downstream_outcome: String,
    pub policy_revision: u64,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMutationRequest {
    pub schema_version: String,
    pub operation: String,
    pub layer: super::policy_control::PolicyLayer,
    pub revision: u64,
    pub observed_at: u64,
    pub expires_at: u64,
    pub approver_id: String,
    pub approver_role: String,
    pub simulation_receipt_ids: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySimulationRequest {
    pub schema_version: String,
    pub candidate: super::policy_control::SignedPolicyBundleV2,
    pub requests: Vec<AuthorityRequestV2>,
    pub observed_at: u64,
}

#[derive(Debug, Serialize)]
pub struct PolicySimulationResult {
    pub schema_version: &'static str,
    pub simulation_receipt_id: String,
    pub candidate_digest: String,
    pub decisions: Vec<crate::policy::PolicyDecision>,
    pub current_decisions: Vec<crate::policy::PolicyDecision>,
    pub allow_count: usize,
    pub approval_count: usize,
    pub deny_count: usize,
    pub changed_count: usize,
    pub newly_denied_count: usize,
    pub authority_expansion_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutObservationRequest {
    pub schema_version: String,
    pub layer: super::policy_control::PolicyLayer,
    pub revision: u64,
    pub attack_prevention_regression: f64,
    pub utility_regression: f64,
    pub sample_count: u64,
    pub maximum_attack_regression: f64,
    pub maximum_utility_regression: f64,
    pub observed_at: u64,
    pub expires_at: u64,
    pub observer_id: String,
    pub observer_role: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryQueryRequest {
    pub schema_version: String,
    pub trace_id: String,
    pub limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayQueryRequest {
    pub schema_version: String,
    pub trace_id: String,
    pub observed_at: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAccessRequest {
    pub schema_version: String,
    pub request_id: String,
    pub trace_id: String,
    pub content_ref: String,
    pub tenant_id: String,
    pub requester_id: String,
    pub requester_role: String,
    pub purpose: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardEvent {
    pub schema_version: &'static str,
    pub event_id: String,
    pub trace_id: String,
    pub stage: String,
    pub subject: RuntimeSubject,
    pub content_refs: Vec<String>,
    pub capability_id: Option<String>,
    pub resource_ref: Option<String>,
    pub policy_revision: Option<u64>,
    pub decision: String,
    pub reason_codes: Vec<String>,
    pub enforcement: EventEnforcement,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventEnforcement {
    pub downstream_dispatched: bool,
    pub receipt_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub reason_code: String,
}
