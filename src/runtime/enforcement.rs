use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::atomic_store;
use super::contracts::{AuthorityRequestV2, ExecutionReceipt, EXECUTION_RECEIPT_VERSION};
use super::crypto;
use crate::policy::PolicyEffect;

pub const CAPABILITY_REGISTRATION_VERSION: &str = "armorer-guard-capability-registration/v1";
pub const APPROVAL_CHALLENGE_VERSION: &str = "armorer-guard-approval-challenge/v1";
pub const APPROVAL_RECEIPT_VERSION: &str = "armorer-guard-approval-receipt/v1";
pub const APPROVAL_CONSUME_VERSION: &str = "armorer-guard-approval-consume/v1";
pub const EXECUTION_TOKEN_VERSION: &str = "armorer-guard-execution-token/v1";
pub const EXECUTION_REPORT_VERSION: &str = "armorer-guard-execution-report/v1";
pub const EXECUTION_DISPATCH_VERSION: &str = "armorer-guard-execution-dispatch/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySpec {
    pub id: String,
    pub resource_type: String,
    pub operation_class: String,
    pub required_receipt: bool,
    pub fail_mode: String,
    #[serde(default)]
    pub max_dispatches_per_minute: Option<u32>,
    #[serde(default)]
    pub max_in_flight: Option<u32>,
    #[serde(default)]
    pub max_arguments_bytes: Option<usize>,
    #[serde(default)]
    pub failure_threshold_per_minute: Option<u32>,
    #[serde(default)]
    pub circuit_break_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRegistration {
    pub schema_version: String,
    pub capability: CapabilitySpec,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeRequest {
    pub schema_version: String,
    pub authority_request: AuthorityRequestV2,
    pub required_role: String,
    pub expires_at: u64,
    pub maximum_usage_count: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallenge {
    pub schema_version: String,
    pub challenge_id: String,
    pub request_id: String,
    pub agent_id: String,
    pub workload_identity: String,
    pub tenant_id: String,
    pub capability_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub arguments_digest: String,
    pub authority_binding_digest: String,
    pub policy_revision: u64,
    pub required_role: String,
    pub expires_at: u64,
    pub maximum_usage_count: u32,
    pub presentation: ApprovalPresentation,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPresentation {
    pub operation_class: String,
    pub normalized_arguments: serde_json::Value,
    pub destination: Option<String>,
    pub data_classes: Vec<String>,
    pub content_refs: Vec<String>,
    pub contains_untrusted_content: bool,
    pub risk_score: f64,
    pub risk_uncertainty: Option<f64>,
    pub irreversible: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub challenge: ApprovalChallenge,
    pub approver_id: String,
    pub approver_role: String,
    pub approved_at: u64,
    pub expires_at: u64,
    pub maximum_usage_count: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsumeRequest {
    pub schema_version: String,
    pub receipt: ApprovalReceipt,
    pub authority_request: AuthorityRequestV2,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalConsumeResult {
    pub receipt_id: String,
    pub accepted: bool,
    pub remaining_usage_count: u32,
    pub bound_request_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionToken {
    pub schema_version: String,
    pub token_id: String,
    pub decision_id: String,
    pub request_id: String,
    pub agent_id: String,
    pub workload_identity: String,
    pub tenant_id: String,
    pub capability_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub arguments_digest: String,
    pub policy_revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub maximum_usage_count: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReportRequest {
    pub schema_version: String,
    pub token: ExecutionToken,
    pub downstream_dispatched: bool,
    pub downstream_outcome: String,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDispatchRequest {
    pub schema_version: String,
    pub token: ExecutionToken,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutionDispatchGrant {
    pub schema_version: &'static str,
    pub token_id: String,
    pub authorized: bool,
    pub capability_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub arguments_digest: String,
    pub authorized_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApprovalGrant {
    receipt: ApprovalReceipt,
    remaining_usage_count: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct EnforcementSnapshot {
    capabilities: BTreeMap<String, CapabilitySpec>,
    challenges: BTreeMap<String, ApprovalChallenge>,
    approval_grants: BTreeMap<String, ApprovalGrant>,
    issued_tokens: BTreeMap<String, ExecutionToken>,
    consumed_token_ids: HashSet<String>,
    #[serde(default)]
    reported_token_ids: HashSet<String>,
    #[serde(default)]
    dispatch_history: BTreeMap<String, Vec<u64>>,
    #[serde(default)]
    in_flight: BTreeMap<String, HashSet<String>>,
    #[serde(default)]
    failure_history: BTreeMap<String, Vec<u64>>,
    #[serde(default)]
    circuit_open_until: BTreeMap<String, u64>,
}

pub struct EnforcementEngine {
    state_path: PathBuf,
    receipt_path: PathBuf,
    token_key: Vec<u8>,
    approval_key: Vec<u8>,
    state: EnforcementSnapshot,
}

impl EnforcementEngine {
    pub fn load(root: PathBuf, token_key: Vec<u8>, approval_key: Vec<u8>) -> Result<Self, String> {
        if token_key.len() < 32 || approval_key.len() < 32 {
            return Err(
                "execution-token and approval keys must contain at least 32 bytes".to_string(),
            );
        }
        let state_path = root.join("enforcement-state.json");
        let receipt_path = root.join("execution-receipts.jsonl");
        let state = atomic_store::read_json(&state_path)?.unwrap_or_default();
        Ok(Self {
            state_path,
            receipt_path,
            token_key,
            approval_key,
            state,
        })
    }

    pub fn ready(&self) -> bool {
        true
    }

    pub fn capabilities(&self) -> Vec<CapabilitySpec> {
        self.state.capabilities.values().cloned().collect()
    }

    pub fn operational_status(&self, observed_at: u64) -> serde_json::Value {
        let in_flight = self
            .state
            .in_flight
            .values()
            .map(HashSet::len)
            .sum::<usize>();
        let open_circuits = self
            .state
            .circuit_open_until
            .values()
            .filter(|until| **until > observed_at)
            .count();
        serde_json::json!({
            "in_flight": in_flight,
            "open_circuits": open_circuits,
            "registered_capabilities": self.state.capabilities.len(),
        })
    }

    pub fn register_capability(
        &mut self,
        registration: CapabilityRegistration,
    ) -> Result<(), String> {
        if registration.schema_version != CAPABILITY_REGISTRATION_VERSION {
            return Err("unsupported capability registration schema".to_string());
        }
        validate_capability(&registration.capability)?;
        if let Some(existing) = self.state.capabilities.get(&registration.capability.id) {
            if existing.resource_type != registration.capability.resource_type
                || existing.operation_class != registration.capability.operation_class
            {
                return Err(
                    "capability identity is already bound to different semantics".to_string(),
                );
            }
        }
        self.state
            .capabilities
            .insert(registration.capability.id.clone(), registration.capability);
        self.persist()
    }

    pub fn validate_capability(
        &self,
        request: &AuthorityRequestV2,
    ) -> Result<&CapabilitySpec, String> {
        let capability = self
            .state
            .capabilities
            .get(&request.action.capability_id)
            .ok_or_else(|| "capability is not registered with Guard".to_string())?;
        if capability.resource_type != request.resource.resource_type {
            return Err(
                "capability resource type does not match the authority request".to_string(),
            );
        }
        if capability.operation_class != request.action.operation_class {
            return Err(
                "capability operation class does not match the authority request".to_string(),
            );
        }
        if capability.max_arguments_bytes.is_some_and(|maximum| {
            crypto::canonical_bytes(&request.action.normalized_arguments)
                .map(|bytes| bytes.len() > maximum)
                .unwrap_or(true)
        }) {
            return Err("capability arguments exceed the configured budget".to_string());
        }
        Ok(capability)
    }

    pub fn create_challenge(
        &mut self,
        request: ApprovalChallengeRequest,
        policy_revision: u64,
        observed_at: u64,
    ) -> Result<ApprovalChallenge, String> {
        if request.schema_version != APPROVAL_CHALLENGE_VERSION
            || request.expires_at <= observed_at
            || request.maximum_usage_count == 0
            || request.maximum_usage_count > 100
            || request.required_role.trim().is_empty()
        {
            return Err("approval challenge request is invalid".to_string());
        }
        self.validate_capability(&request.authority_request)?;
        let mut warnings = Vec::new();
        if request
            .authority_request
            .influence
            .contains_untrusted_content
        {
            warnings.push("untrusted content influenced this action request".to_string());
        }
        if !request.authority_request.resource.data_classes.is_empty() {
            warnings.push("the target is data-classified".to_string());
        }
        let irreversible = matches!(
            request.authority_request.action.operation_class.as_str(),
            "destructive" | "credential" | "external_send" | "code_execution"
        );
        let authority_binding_digest = approval_binding_digest(&request.authority_request)?;
        let destination = ["destination", "url", "to", "recipient"]
            .iter()
            .find_map(|key| {
                request.authority_request.action.normalized_arguments[*key]
                    .as_str()
                    .map(str::to_string)
            });
        let mut challenge = ApprovalChallenge {
            schema_version: APPROVAL_CHALLENGE_VERSION.to_string(),
            challenge_id: String::new(),
            request_id: request.authority_request.request_id,
            agent_id: request.authority_request.subject.agent_id,
            workload_identity: request.authority_request.subject.workload_identity,
            tenant_id: request.authority_request.subject.tenant_id,
            capability_id: request.authority_request.action.capability_id,
            resource_type: request.authority_request.resource.resource_type,
            resource_id: request.authority_request.resource.resource_id,
            arguments_digest: crypto::digest(
                &request.authority_request.action.normalized_arguments,
            )?,
            authority_binding_digest,
            policy_revision,
            required_role: request.required_role,
            expires_at: request.expires_at,
            maximum_usage_count: request.maximum_usage_count,
            presentation: ApprovalPresentation {
                operation_class: request.authority_request.action.operation_class,
                normalized_arguments: request.authority_request.action.normalized_arguments,
                destination,
                data_classes: request.authority_request.resource.data_classes,
                content_refs: request.authority_request.influence.content_refs,
                contains_untrusted_content: request
                    .authority_request
                    .influence
                    .contains_untrusted_content,
                risk_score: request.authority_request.context.risk_score,
                risk_uncertainty: None,
                irreversible,
                warnings,
            },
        };
        challenge.challenge_id = crypto::addressed_id("approval-challenge", &challenge);
        self.state
            .challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        self.persist()?;
        Ok(challenge)
    }

    pub fn consume_approval(
        &mut self,
        request: ApprovalConsumeRequest,
    ) -> Result<ApprovalConsumeResult, String> {
        if request.schema_version != APPROVAL_CONSUME_VERSION {
            return Err("unsupported approval consumption schema".to_string());
        }
        validate_approval_receipt(&request.receipt, &self.approval_key, request.observed_at)?;
        let stored = self
            .state
            .challenges
            .get(&request.receipt.challenge.challenge_id)
            .ok_or_else(|| "approval challenge is unknown".to_string())?;
        if crypto::digest(stored)? != crypto::digest(&request.receipt.challenge)? {
            return Err(
                "approval receipt challenge does not match the stored challenge".to_string(),
            );
        }
        if request.receipt.approver_role != stored.required_role {
            return Err("approver role does not satisfy the challenge".to_string());
        }
        ensure_request_binding(stored, &request.authority_request)?;
        if self
            .state
            .approval_grants
            .contains_key(&request.receipt.receipt_id)
        {
            return Err("approval receipt has already been consumed".to_string());
        }
        let usage = request
            .receipt
            .maximum_usage_count
            .min(stored.maximum_usage_count);
        self.state.approval_grants.insert(
            request.receipt.receipt_id.clone(),
            ApprovalGrant {
                receipt: request.receipt.clone(),
                remaining_usage_count: usage,
            },
        );
        self.persist()?;
        Ok(ApprovalConsumeResult {
            receipt_id: request.receipt.receipt_id,
            accepted: true,
            remaining_usage_count: usage,
            bound_request_id: stored.request_id.clone(),
        })
    }

    pub fn approval_roles_for(
        &mut self,
        request: &AuthorityRequestV2,
    ) -> Result<Vec<String>, String> {
        let mut roles = Vec::new();
        for receipt_id in &request.context.approval_receipts {
            let Some(grant) = self.state.approval_grants.get_mut(receipt_id) else {
                continue;
            };
            if grant.remaining_usage_count == 0
                || grant.receipt.expires_at <= request.context.observed_at
                || ensure_request_binding(&grant.receipt.challenge, request).is_err()
            {
                continue;
            }
            grant.remaining_usage_count -= 1;
            if !roles.contains(&grant.receipt.approver_role) {
                roles.push(grant.receipt.approver_role.clone());
            }
        }
        if !request.context.approval_receipts.is_empty() {
            self.persist()?;
        }
        Ok(roles)
    }

    pub fn issue_token(
        &mut self,
        request: &AuthorityRequestV2,
        decision_id: &str,
        policy_revision: u64,
        observed_at: u64,
    ) -> Result<ExecutionToken, String> {
        self.validate_capability(request)?;
        let mut token = ExecutionToken {
            schema_version: EXECUTION_TOKEN_VERSION.to_string(),
            token_id: crypto::opaque_id("execution-token", &self.token_key),
            decision_id: decision_id.to_string(),
            request_id: request.request_id.clone(),
            agent_id: request.subject.agent_id.clone(),
            workload_identity: request.subject.workload_identity.clone(),
            tenant_id: request.subject.tenant_id.clone(),
            capability_id: request.action.capability_id.clone(),
            resource_type: request.resource.resource_type.clone(),
            resource_id: request.resource.resource_id.clone(),
            arguments_digest: crypto::digest(&request.action.normalized_arguments)?,
            policy_revision,
            issued_at: observed_at,
            expires_at: observed_at.saturating_add(30),
            maximum_usage_count: 1,
            signature: String::new(),
        };
        token.signature = sign_execution_token(&self.token_key, &token)?;
        self.state
            .issued_tokens
            .insert(token.token_id.clone(), token.clone());
        Ok(token)
    }

    pub fn record_non_dispatch(
        &self,
        decision_id: &str,
        capability_id: &str,
        effect: PolicyEffect,
        policy_revision: u64,
        observed_at: u64,
    ) -> Result<ExecutionReceipt, String> {
        if effect == PolicyEffect::Allow {
            return Err("an allow decision is not proof of non-dispatch".to_string());
        }
        let seed = serde_json::json!({
            "decision_id": decision_id,
            "capability_id": capability_id,
            "effect": effect,
            "observed_at": observed_at,
        });
        let receipt = ExecutionReceipt {
            schema_version: EXECUTION_RECEIPT_VERSION,
            receipt_id: crypto::addressed_id("execution-receipt", &seed),
            decision_id: decision_id.to_string(),
            execution_token_id: None,
            capability_id: capability_id.to_string(),
            effect,
            downstream_dispatched: false,
            downstream_outcome: "not_executed".to_string(),
            policy_revision,
            observed_at,
        };
        atomic_store::append_json(&self.receipt_path, &receipt)?;
        Ok(receipt)
    }

    pub fn record_execution(
        &mut self,
        report: ExecutionReportRequest,
    ) -> Result<ExecutionReceipt, String> {
        if report.schema_version != EXECUTION_REPORT_VERSION
            || report.downstream_outcome.trim().is_empty()
        {
            return Err("execution report is invalid".to_string());
        }
        verify_execution_token_integrity(&self.token_key, &report.token, report.observed_at)?;
        let issued = self
            .state
            .issued_tokens
            .get(&report.token.token_id)
            .ok_or_else(|| "execution token was not issued by this Guard instance".to_string())?;
        if crypto::digest(issued)? != crypto::digest(&report.token)? {
            return Err("execution token does not match the issued token".to_string());
        }
        if !self
            .state
            .consumed_token_ids
            .contains(&report.token.token_id)
        {
            return Err("execution token was not authorized for dispatch".to_string());
        }
        if !self
            .state
            .reported_token_ids
            .insert(report.token.token_id.clone())
        {
            return Err("execution outcome has already been reported".to_string());
        }
        let capability_key = format!("{}|{}", report.token.agent_id, report.token.capability_id);
        if let Some(tokens) = self.state.in_flight.get_mut(&capability_key) {
            tokens.remove(&report.token.token_id);
        }
        if report.downstream_outcome != "succeeded" {
            let capability = self
                .state
                .capabilities
                .get(&report.token.capability_id)
                .cloned();
            if let Some(capability) = capability {
                if let (Some(threshold), Some(cooldown)) = (
                    capability.failure_threshold_per_minute,
                    capability.circuit_break_seconds,
                ) {
                    let failures = self
                        .state
                        .failure_history
                        .entry(capability_key.clone())
                        .or_default();
                    let window_start = report.observed_at.saturating_sub(60);
                    failures.retain(|observed| *observed > window_start);
                    failures.push(report.observed_at);
                    if failures.len() >= threshold as usize {
                        self.state.circuit_open_until.insert(
                            capability_key.clone(),
                            report.observed_at.saturating_add(cooldown),
                        );
                    }
                }
            }
        }
        let seed = serde_json::json!({
            "token_id": report.token.token_id,
            "dispatched": report.downstream_dispatched,
            "outcome": report.downstream_outcome,
            "observed_at": report.observed_at,
        });
        let receipt = ExecutionReceipt {
            schema_version: EXECUTION_RECEIPT_VERSION,
            receipt_id: crypto::addressed_id("execution-receipt", &seed),
            decision_id: report.token.decision_id.clone(),
            execution_token_id: Some(report.token.token_id.clone()),
            capability_id: report.token.capability_id.clone(),
            effect: PolicyEffect::Allow,
            downstream_dispatched: report.downstream_dispatched,
            downstream_outcome: report.downstream_outcome,
            policy_revision: report.token.policy_revision,
            observed_at: report.observed_at,
        };
        atomic_store::append_json(&self.receipt_path, &receipt)?;
        self.persist()?;
        Ok(receipt)
    }

    pub fn authorize_dispatch(
        &mut self,
        request: ExecutionDispatchRequest,
    ) -> Result<ExecutionDispatchGrant, String> {
        if request.schema_version != EXECUTION_DISPATCH_VERSION {
            return Err("unsupported execution dispatch schema".to_string());
        }
        verify_execution_token(&self.token_key, &request.token, request.observed_at)?;
        let issued = self
            .state
            .issued_tokens
            .get(&request.token.token_id)
            .ok_or_else(|| "execution token was not issued by this Guard instance".to_string())?;
        if crypto::digest(issued)? != crypto::digest(&request.token)? {
            return Err("execution token does not match the issued token".to_string());
        }
        if !self
            .state
            .consumed_token_ids
            .insert(request.token.token_id.clone())
        {
            return Err("execution token has already been consumed".to_string());
        }
        let capability = self
            .state
            .capabilities
            .get(&request.token.capability_id)
            .cloned()
            .ok_or_else(|| "execution token capability is no longer registered".to_string())?;
        let key = format!("{}|{}", request.token.agent_id, request.token.capability_id);
        if self
            .state
            .circuit_open_until
            .get(&key)
            .is_some_and(|until| *until > request.observed_at)
        {
            self.state
                .consumed_token_ids
                .remove(&request.token.token_id);
            return Err("capability circuit breaker is open".to_string());
        }
        let expired_tokens = self
            .state
            .issued_tokens
            .iter()
            .filter(|(_, token)| token.expires_at <= request.observed_at)
            .map(|(token_id, _)| token_id.clone())
            .collect::<HashSet<_>>();
        let in_flight = self.state.in_flight.entry(key.clone()).or_default();
        in_flight.retain(|token_id| !expired_tokens.contains(token_id));
        if capability
            .max_in_flight
            .is_some_and(|maximum| in_flight.len() >= maximum as usize)
        {
            self.state
                .consumed_token_ids
                .remove(&request.token.token_id);
            return Err("capability in-flight budget exceeded".to_string());
        }
        if let Some(limit) = capability.max_dispatches_per_minute {
            let history = self.state.dispatch_history.entry(key).or_default();
            let window_start = request.observed_at.saturating_sub(60);
            history.retain(|observed| *observed > window_start);
            if history.len() >= limit as usize {
                self.state
                    .consumed_token_ids
                    .remove(&request.token.token_id);
                return Err("capability dispatch rate limit exceeded".to_string());
            }
            history.push(request.observed_at);
        }
        self.state
            .in_flight
            .entry(format!(
                "{}|{}",
                request.token.agent_id, request.token.capability_id
            ))
            .or_default()
            .insert(request.token.token_id.clone());
        self.persist()?;
        Ok(ExecutionDispatchGrant {
            schema_version: "armorer-guard-execution-dispatch-grant/v1",
            token_id: request.token.token_id,
            authorized: true,
            capability_id: request.token.capability_id,
            resource_type: request.token.resource_type,
            resource_id: request.token.resource_id,
            arguments_digest: request.token.arguments_digest,
            authorized_at: request.observed_at,
        })
    }

    fn persist(&self) -> Result<(), String> {
        atomic_store::atomic_json(&self.state_path, &self.state)
    }
}

pub fn verify_execution_token(
    key: &[u8],
    token: &ExecutionToken,
    observed_at: u64,
) -> Result<(), String> {
    if token.schema_version != EXECUTION_TOKEN_VERSION
        || token.maximum_usage_count != 1
        || token.expires_at <= observed_at
        || token.issued_at > observed_at
        || token.tenant_id.trim().is_empty()
        || token.capability_id.trim().is_empty()
    {
        return Err("execution token is invalid or expired".to_string());
    }
    let mut unsigned = token.clone();
    unsigned.signature.clear();
    if !crypto::verify(key, &unsigned, &token.signature) {
        return Err("execution token signature verification failed".to_string());
    }
    Ok(())
}

fn verify_execution_token_integrity(
    key: &[u8],
    token: &ExecutionToken,
    observed_at: u64,
) -> Result<(), String> {
    if token.schema_version != EXECUTION_TOKEN_VERSION
        || token.maximum_usage_count != 1
        || token.issued_at > observed_at
        || token.tenant_id.trim().is_empty()
        || token.capability_id.trim().is_empty()
    {
        return Err("execution token integrity is invalid".to_string());
    }
    let mut unsigned = token.clone();
    unsigned.signature.clear();
    if !crypto::verify(key, &unsigned, &token.signature) {
        return Err("execution token signature verification failed".to_string());
    }
    Ok(())
}

fn sign_execution_token(key: &[u8], token: &ExecutionToken) -> Result<String, String> {
    let mut unsigned = token.clone();
    unsigned.signature.clear();
    crypto::sign(key, &unsigned)
}

fn validate_approval_receipt(
    receipt: &ApprovalReceipt,
    key: &[u8],
    observed_at: u64,
) -> Result<(), String> {
    if receipt.schema_version != APPROVAL_RECEIPT_VERSION
        || receipt.approver_id.trim().is_empty()
        || receipt.approver_role.trim().is_empty()
        || receipt.maximum_usage_count == 0
        || receipt.expires_at <= observed_at
        || receipt.approved_at > observed_at
        || receipt.expires_at > receipt.challenge.expires_at
    {
        return Err("approval receipt metadata is invalid or expired".to_string());
    }
    let expected_id = approval_receipt_id(receipt);
    if receipt.receipt_id != expected_id {
        return Err("approval receipt ID is not content-addressed".to_string());
    }
    let mut unsigned = receipt.clone();
    unsigned.signature.clear();
    if !crypto::verify(key, &unsigned, &receipt.signature) {
        return Err("approval receipt signature verification failed".to_string());
    }
    Ok(())
}

fn approval_receipt_id(receipt: &ApprovalReceipt) -> String {
    let mut identity_payload = receipt.clone();
    identity_payload.receipt_id.clear();
    identity_payload.signature.clear();
    crypto::addressed_id("approval-receipt", &identity_payload)
}

fn ensure_request_binding(
    challenge: &ApprovalChallenge,
    request: &AuthorityRequestV2,
) -> Result<(), String> {
    if challenge.request_id != request.request_id
        || challenge.agent_id != request.subject.agent_id
        || challenge.workload_identity != request.subject.workload_identity
        || challenge.tenant_id != request.subject.tenant_id
        || challenge.capability_id != request.action.capability_id
        || challenge.resource_type != request.resource.resource_type
        || challenge.resource_id != request.resource.resource_id
        || challenge.arguments_digest != crypto::digest(&request.action.normalized_arguments)?
        || challenge.authority_binding_digest != approval_binding_digest(request)?
    {
        return Err("approval does not bind the exact authority request".to_string());
    }
    Ok(())
}

fn approval_binding_digest(request: &AuthorityRequestV2) -> Result<String, String> {
    let mut bound = request.clone();
    bound.context.approval_receipts.clear();
    crypto::digest(&bound)
}

fn validate_capability(capability: &CapabilitySpec) -> Result<(), String> {
    if capability.id.trim().is_empty()
        || capability.resource_type.trim().is_empty()
        || capability.operation_class.trim().is_empty()
        || !matches!(
            capability.fail_mode.as_str(),
            "closed" | "cached" | "review"
        )
        || matches!(
            capability.operation_class.as_str(),
            "destructive" | "credential" | "external_send"
        ) && capability.fail_mode != "closed"
        || capability.max_dispatches_per_minute == Some(0)
        || capability.max_in_flight == Some(0)
        || capability.max_arguments_bytes == Some(0)
        || capability.failure_threshold_per_minute == Some(0)
        || capability.circuit_break_seconds == Some(0)
        || capability.failure_threshold_per_minute.is_some()
            != capability.circuit_break_seconds.is_some()
    {
        return Err("capability registration is invalid or fail-open".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::contracts::{
        AuthorityActionV2, AuthorityContextV2, AuthorityDelegationV2, AuthorityInfluenceV2,
        AuthorityResourceV2, AuthoritySubjectV2, AUTHORITY_REQUEST_VERSION,
    };
    use super::*;

    fn request() -> AuthorityRequestV2 {
        AuthorityRequestV2 {
            schema_version: AUTHORITY_REQUEST_VERSION.to_string(),
            request_id: "authority-request/1".to_string(),
            subject: AuthoritySubjectV2 {
                agent_id: "agent".to_string(),
                workload_identity: "spiffe://tenant/agent".to_string(),
                tenant_id: "tenant".to_string(),
            },
            delegation: AuthorityDelegationV2 {
                delegated_by: "user/operator".to_string(),
                capability_ids: vec!["case.delete".to_string()],
                purpose: "retention".to_string(),
                depth: 1,
                expires_at: 1_000,
                signature: "signature".to_string(),
            },
            action: AuthorityActionV2 {
                capability_id: "case.delete".to_string(),
                operation_class: "destructive".to_string(),
                normalized_arguments: serde_json::json!({"case_id":"case/1"}),
            },
            resource: AuthorityResourceV2 {
                resource_type: "case".to_string(),
                resource_id: "case/1".to_string(),
                tenant_id: "tenant".to_string(),
                data_classes: vec![],
            },
            influence: AuthorityInfluenceV2 {
                content_refs: vec![],
                contains_untrusted_content: false,
            },
            context: AuthorityContextV2 {
                trace_id: "trace/1".to_string(),
                session_id: "session/1".to_string(),
                risk_score: 1.0,
                observed_at: 100,
                approval_receipts: vec![],
            },
        }
    }

    fn engine() -> EnforcementEngine {
        let root = std::env::temp_dir()
            .join(crypto::opaque_id("guard-enforcement-test", &[4; 32]).replace('/', "-"));
        let mut engine = EnforcementEngine::load(root, vec![4; 32], vec![5; 32]).unwrap();
        engine
            .register_capability(CapabilityRegistration {
                schema_version: CAPABILITY_REGISTRATION_VERSION.to_string(),
                capability: CapabilitySpec {
                    id: "case.delete".to_string(),
                    resource_type: "case".to_string(),
                    operation_class: "destructive".to_string(),
                    required_receipt: true,
                    fail_mode: "closed".to_string(),
                    max_dispatches_per_minute: Some(10),
                    max_in_flight: None,
                    max_arguments_bytes: None,
                    failure_threshold_per_minute: None,
                    circuit_break_seconds: None,
                },
            })
            .unwrap();
        engine
    }

    fn configure_limits(
        engine: &mut EnforcementEngine,
        max_in_flight: Option<u32>,
        max_arguments_bytes: Option<usize>,
        failure_threshold_per_minute: Option<u32>,
        circuit_break_seconds: Option<u64>,
    ) {
        engine
            .register_capability(CapabilityRegistration {
                schema_version: CAPABILITY_REGISTRATION_VERSION.to_string(),
                capability: CapabilitySpec {
                    id: "case.delete".to_string(),
                    resource_type: "case".to_string(),
                    operation_class: "destructive".to_string(),
                    required_receipt: true,
                    fail_mode: "closed".to_string(),
                    max_dispatches_per_minute: Some(10),
                    max_in_flight,
                    max_arguments_bytes,
                    failure_threshold_per_minute,
                    circuit_break_seconds,
                },
            })
            .unwrap();
    }

    #[test]
    fn argument_mutation_invalidates_approval() {
        let mut engine = engine();
        let authority = request();
        let challenge = engine
            .create_challenge(
                ApprovalChallengeRequest {
                    schema_version: APPROVAL_CHALLENGE_VERSION.to_string(),
                    authority_request: authority.clone(),
                    required_role: "case_owner".to_string(),
                    expires_at: 500,
                    maximum_usage_count: 1,
                },
                7,
                100,
            )
            .unwrap();
        let mut receipt = ApprovalReceipt {
            schema_version: APPROVAL_RECEIPT_VERSION.to_string(),
            receipt_id: String::new(),
            challenge,
            approver_id: "user/owner".to_string(),
            approver_role: "case_owner".to_string(),
            approved_at: 101,
            expires_at: 400,
            maximum_usage_count: 1,
            signature: String::new(),
        };
        receipt.receipt_id = approval_receipt_id(&receipt);
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        receipt.signature = crypto::sign(&[5; 32], &unsigned).unwrap();
        let mut mutated = authority;
        mutated.action.normalized_arguments = serde_json::json!({"case_id":"case/2"});
        assert!(engine
            .consume_approval(ApprovalConsumeRequest {
                schema_version: APPROVAL_CONSUME_VERSION.to_string(),
                receipt,
                authority_request: mutated,
                observed_at: 102,
            })
            .is_err());
    }

    #[test]
    fn approval_presentation_exposes_risk_and_binds_provenance() {
        let mut engine = engine();
        let mut authority = request();
        authority.resource.data_classes = vec!["legal_privileged".to_string()];
        authority.influence.content_refs = vec!["content/sha256:document".to_string()];
        authority.influence.contains_untrusted_content = true;
        authority.context.risk_score = 94.0;
        let challenge = engine
            .create_challenge(
                ApprovalChallengeRequest {
                    schema_version: APPROVAL_CHALLENGE_VERSION.to_string(),
                    authority_request: authority.clone(),
                    required_role: "case_owner".to_string(),
                    expires_at: 500,
                    maximum_usage_count: 1,
                },
                7,
                100,
            )
            .unwrap();
        assert_eq!(
            challenge.presentation.normalized_arguments,
            serde_json::json!({"case_id":"case/1"})
        );
        assert!(challenge.presentation.contains_untrusted_content);
        assert!(challenge.presentation.irreversible);
        assert_eq!(challenge.presentation.risk_score, 94.0);

        let mut receipt = ApprovalReceipt {
            schema_version: APPROVAL_RECEIPT_VERSION.to_string(),
            receipt_id: String::new(),
            challenge,
            approver_id: "user/owner".to_string(),
            approver_role: "case_owner".to_string(),
            approved_at: 101,
            expires_at: 400,
            maximum_usage_count: 1,
            signature: String::new(),
        };
        receipt.receipt_id = approval_receipt_id(&receipt);
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        receipt.signature = crypto::sign(&[5; 32], &unsigned).unwrap();
        authority.influence.content_refs = vec!["content/sha256:different".to_string()];
        assert!(engine
            .consume_approval(ApprovalConsumeRequest {
                schema_version: APPROVAL_CONSUME_VERSION.to_string(),
                receipt,
                authority_request: authority,
                observed_at: 102,
            })
            .is_err());
    }

    #[test]
    fn valid_approval_is_content_addressed_and_consumable() {
        let mut engine = engine();
        let authority = request();
        let challenge = engine
            .create_challenge(
                ApprovalChallengeRequest {
                    schema_version: APPROVAL_CHALLENGE_VERSION.to_string(),
                    authority_request: authority.clone(),
                    required_role: "case_owner".to_string(),
                    expires_at: 500,
                    maximum_usage_count: 1,
                },
                7,
                100,
            )
            .unwrap();
        let mut receipt = ApprovalReceipt {
            schema_version: APPROVAL_RECEIPT_VERSION.to_string(),
            receipt_id: String::new(),
            challenge,
            approver_id: "user/owner".to_string(),
            approver_role: "case_owner".to_string(),
            approved_at: 101,
            expires_at: 400,
            maximum_usage_count: 1,
            signature: String::new(),
        };
        receipt.receipt_id = approval_receipt_id(&receipt);
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        receipt.signature = crypto::sign(&[5; 32], &unsigned).unwrap();
        let result = engine
            .consume_approval(ApprovalConsumeRequest {
                schema_version: APPROVAL_CONSUME_VERSION.to_string(),
                receipt,
                authority_request: authority,
                observed_at: 102,
            })
            .unwrap();
        assert!(result.accepted);
        assert_eq!(result.remaining_usage_count, 1);
    }

    #[test]
    fn execution_tokens_are_single_use() {
        let mut engine = engine();
        let token = engine
            .issue_token(&request(), "decision/1", 7, 100)
            .unwrap();
        let report = ExecutionReportRequest {
            schema_version: EXECUTION_REPORT_VERSION.to_string(),
            token,
            downstream_dispatched: true,
            downstream_outcome: "succeeded".to_string(),
            observed_at: 101,
        };
        assert!(engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: report.token.clone(),
                observed_at: 101,
            })
            .is_ok());
        assert!(engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: report.token.clone(),
                observed_at: 101,
            })
            .is_err());
        assert!(engine.record_execution(report.clone()).is_ok());
        assert!(engine.record_execution(report).is_err());
    }

    #[test]
    fn dispatch_consumption_survives_restart() {
        let root = std::env::temp_dir()
            .join(crypto::opaque_id("guard-enforcement-restart", &[4; 32]).replace('/', "-"));
        let mut engine = EnforcementEngine::load(root.clone(), vec![4; 32], vec![5; 32]).unwrap();
        engine
            .register_capability(CapabilityRegistration {
                schema_version: CAPABILITY_REGISTRATION_VERSION.to_string(),
                capability: CapabilitySpec {
                    id: "case.delete".to_string(),
                    resource_type: "case".to_string(),
                    operation_class: "destructive".to_string(),
                    required_receipt: true,
                    fail_mode: "closed".to_string(),
                    max_dispatches_per_minute: Some(10),
                    max_in_flight: None,
                    max_arguments_bytes: None,
                    failure_threshold_per_minute: None,
                    circuit_break_seconds: None,
                },
            })
            .unwrap();
        let token = engine
            .issue_token(&request(), "decision/restart", 7, 100)
            .unwrap();
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: token.clone(),
                observed_at: 101,
            })
            .unwrap();
        drop(engine);

        let mut recovered = EnforcementEngine::load(root, vec![4; 32], vec![5; 32]).unwrap();
        assert!(recovered
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: token.clone(),
                observed_at: 102,
            })
            .is_err());
        assert!(recovered
            .record_execution(ExecutionReportRequest {
                schema_version: EXECUTION_REPORT_VERSION.to_string(),
                token,
                downstream_dispatched: true,
                downstream_outcome: "succeeded".to_string(),
                observed_at: 102,
            })
            .is_ok());
    }

    #[test]
    fn argument_and_in_flight_budgets_fail_closed() {
        let mut engine = engine();
        configure_limits(&mut engine, Some(1), Some(128), None, None);
        let first = engine
            .issue_token(&request(), "decision/first", 7, 100)
            .unwrap();
        let second = engine
            .issue_token(&request(), "decision/second", 7, 100)
            .unwrap();
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: first.clone(),
                observed_at: 101,
            })
            .unwrap();
        assert!(engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: second.clone(),
                observed_at: 101,
            })
            .unwrap_err()
            .contains("in-flight"));
        engine
            .record_execution(ExecutionReportRequest {
                schema_version: EXECUTION_REPORT_VERSION.to_string(),
                token: first,
                downstream_dispatched: true,
                downstream_outcome: "succeeded".to_string(),
                observed_at: 102,
            })
            .unwrap();
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: second,
                observed_at: 103,
            })
            .unwrap();

        configure_limits(&mut engine, Some(1), Some(1), None, None);
        assert!(engine
            .issue_token(&request(), "decision/oversized", 7, 104)
            .unwrap_err()
            .contains("arguments"));
    }

    #[test]
    fn downstream_failures_open_and_recover_the_circuit() {
        let mut engine = engine();
        configure_limits(&mut engine, None, None, Some(1), Some(30));
        let first = engine
            .issue_token(&request(), "decision/fail", 7, 100)
            .unwrap();
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: first.clone(),
                observed_at: 101,
            })
            .unwrap();
        engine
            .record_execution(ExecutionReportRequest {
                schema_version: EXECUTION_REPORT_VERSION.to_string(),
                token: first,
                downstream_dispatched: true,
                downstream_outcome: "failed".to_string(),
                observed_at: 102,
            })
            .unwrap();
        let recovery = engine
            .issue_token(&request(), "decision/recovery", 7, 103)
            .unwrap();
        assert!(engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: recovery.clone(),
                observed_at: 104,
            })
            .unwrap_err()
            .contains("circuit breaker"));
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: recovery,
                observed_at: 132,
            })
            .unwrap();
    }

    #[test]
    fn long_running_effect_can_report_after_token_expiry() {
        let mut engine = engine();
        let token = engine
            .issue_token(&request(), "decision/slow", 7, 100)
            .unwrap();
        engine
            .authorize_dispatch(ExecutionDispatchRequest {
                schema_version: EXECUTION_DISPATCH_VERSION.to_string(),
                token: token.clone(),
                observed_at: 101,
            })
            .unwrap();
        assert!(engine
            .record_execution(ExecutionReportRequest {
                schema_version: EXECUTION_REPORT_VERSION.to_string(),
                token,
                downstream_dispatched: true,
                downstream_outcome: "succeeded".to_string(),
                observed_at: 200,
            })
            .is_ok());
    }

    #[test]
    fn pre_budget_snapshot_upgrades_with_fail_closed_defaults() {
        let root = std::env::temp_dir()
            .join(crypto::opaque_id("guard-enforcement-upgrade", &[4; 32]).replace('/', "-"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("enforcement-state.json"),
            br#"{
                "capabilities":{"case.delete":{
                    "id":"case.delete","resource_type":"case",
                    "operation_class":"destructive","required_receipt":true,
                    "fail_mode":"closed","max_dispatches_per_minute":10
                }},
                "challenges":{},"approval_grants":{},"issued_tokens":{},
                "consumed_token_ids":[],"reported_token_ids":[],"dispatch_history":{}
            }"#,
        )
        .unwrap();
        let engine = EnforcementEngine::load(root, vec![4; 32], vec![5; 32]).unwrap();
        let capability = engine.capabilities().pop().unwrap();
        assert_eq!(capability.fail_mode, "closed");
        assert_eq!(capability.max_in_flight, None);
        assert_eq!(capability.failure_threshold_per_minute, None);
    }

    #[test]
    fn fuzzed_token_and_approval_contracts_never_bypass_signatures() {
        let mut engine = engine();
        let authority = request();
        let token = engine
            .issue_token(&authority, "decision/fuzz", 7, 100)
            .unwrap();
        let challenge = engine
            .create_challenge(
                ApprovalChallengeRequest {
                    schema_version: APPROVAL_CHALLENGE_VERSION.to_string(),
                    authority_request: authority,
                    required_role: "case_owner".to_string(),
                    expires_at: 500,
                    maximum_usage_count: 1,
                },
                7,
                100,
            )
            .unwrap();
        let mut receipt = ApprovalReceipt {
            schema_version: APPROVAL_RECEIPT_VERSION.to_string(),
            receipt_id: String::new(),
            challenge,
            approver_id: "user/owner".to_string(),
            approver_role: "case_owner".to_string(),
            approved_at: 101,
            expires_at: 400,
            maximum_usage_count: 1,
            signature: String::new(),
        };
        receipt.receipt_id = approval_receipt_id(&receipt);
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        receipt.signature = crypto::sign(&[5; 32], &unsigned).unwrap();

        let cases = [
            (serde_json::to_vec(&token).unwrap(), "token"),
            (serde_json::to_vec(&receipt).unwrap(), "approval"),
        ];
        for (seed, kind) in cases {
            for index in 0..seed.len() {
                let mut mutated = seed.clone();
                mutated[index] ^= 1 << (index % 7);
                if kind == "token" {
                    if let Ok(value) = serde_json::from_slice::<ExecutionToken>(&mutated) {
                        if crypto::digest(&value).unwrap() != crypto::digest(&token).unwrap() {
                            assert!(verify_execution_token(&[4; 32], &value, 101).is_err());
                        }
                    }
                } else if let Ok(value) = serde_json::from_slice::<ApprovalReceipt>(&mutated) {
                    if crypto::digest(&value).unwrap() != crypto::digest(&receipt).unwrap() {
                        assert!(validate_approval_receipt(&value, &[5; 32], 102).is_err());
                    }
                }
            }
        }
    }
}
