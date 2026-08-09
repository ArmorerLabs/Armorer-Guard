use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const POLICY_VERSION: &str = "armorer-guard-policy-bundle/v1";
const REQUEST_VERSION: &str = "armorer-guard-authority-request/v1";
const DECISION_VERSION: &str = "armorer-guard-policy-decision/v1";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInvariants {
    pub deny_cross_tenant: bool,
    pub deny_untrusted_privilege_expansion: bool,
    pub deny_guard_tampering: bool,
    pub require_signed_delegation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectSelector {
    pub agent_ids: Vec<String>,
    pub identity_ids: Vec<String>,
    pub tenant_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelector {
    pub resource_types: Vec<String>,
    pub resource_ids: Vec<String>,
    pub tenant_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConditions {
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default)]
    pub required_purposes: Vec<String>,
    #[serde(default)]
    pub required_provenance: Option<String>,
    #[serde(default)]
    pub required_approval_roles: Vec<String>,
    #[serde(default)]
    pub max_delegation_depth: Option<u32>,
    #[serde(default)]
    pub require_resource_tenant_match: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub rule_id: String,
    pub priority: u32,
    pub effect: PolicyEffect,
    pub subjects: SubjectSelector,
    pub actions: Vec<String>,
    pub resources: ResourceSelector,
    #[serde(default)]
    pub conditions: PolicyConditions,
    pub immutable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptivePolicy {
    pub mode: String,
    pub review_risk_threshold: f64,
    pub block_risk_threshold: f64,
    pub allowed_automatic_effects: Vec<PolicyEffect>,
    pub authority_expansion: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: u64,
    pub default_effect: PolicyEffect,
    pub invariants: PolicyInvariants,
    pub rules: Vec<PolicyRule>,
    pub adaptive: AdaptivePolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySubject {
    pub agent_id: String,
    pub identity_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDelegation {
    pub delegated_by: String,
    pub capability_ids: Vec<String>,
    pub purpose: String,
    pub depth: u32,
    pub expires_at: u64,
    pub signature_verified: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityResource {
    pub resource_type: String,
    pub resource_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContext {
    pub provenance: String,
    pub risk_score: f64,
    pub approval_roles: Vec<String>,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequest {
    pub schema_version: String,
    pub request_id: String,
    pub subject: AuthoritySubject,
    pub delegation: AuthorityDelegation,
    pub action: String,
    pub resource: AuthorityResource,
    pub context: AuthorityContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluateInput {
    pub policy_bundle: PolicyBundle,
    pub request: AuthorityRequest,
}

#[derive(Debug, Serialize)]
pub struct PolicyDecision {
    pub schema_version: &'static str,
    pub request_id: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub effect: PolicyEffect,
    pub decision_source: String,
    pub matched_rule_ids: Vec<String>,
    pub reason_codes: Vec<String>,
    pub adaptive_tightening_applied: bool,
    pub authority_expanded: bool,
}

fn bounded(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(|ch| ch.is_control())
}

fn selector_valid(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|value| bounded(value))
}

fn optional_selector_valid(values: &[String]) -> bool {
    values.iter().all(|value| bounded(value))
}

fn unique(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values.iter().all(|value| seen.insert(value.as_str()))
}

fn selector_matches(values: &[String], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value == "*" || value == candidate)
}

fn contains_all(actual: &[String], required: &[String]) -> bool {
    required
        .iter()
        .all(|item| actual.iter().any(|actual| actual == item))
}

pub fn validate_policy_bundle(bundle: &PolicyBundle) -> Result<(), String> {
    if bundle.schema_version != POLICY_VERSION || !bounded(&bundle.policy_id) {
        return Err("policy identity is invalid".to_string());
    }
    if matches!(bundle.default_effect, PolicyEffect::Allow) {
        return Err("policy default may not expand authority".to_string());
    }
    if !bundle.invariants.deny_cross_tenant
        || !bundle.invariants.deny_untrusted_privilege_expansion
        || !bundle.invariants.deny_guard_tampering
        || !bundle.invariants.require_signed_delegation
    {
        return Err("all fixed Guard invariants must remain enabled".to_string());
    }
    if bundle.adaptive.mode != "tightening_only"
        || bundle.adaptive.authority_expansion != "human_approval_required"
        || !(0.0..=1.0).contains(&bundle.adaptive.review_risk_threshold)
        || !(0.0..=1.0).contains(&bundle.adaptive.block_risk_threshold)
        || bundle.adaptive.block_risk_threshold < bundle.adaptive.review_risk_threshold
        || bundle.adaptive.allowed_automatic_effects.is_empty()
        || bundle
            .adaptive
            .allowed_automatic_effects
            .iter()
            .any(|effect| matches!(effect, PolicyEffect::Allow))
    {
        return Err("adaptive policy must be bounded to tightening-only effects".to_string());
    }
    if bundle.rules.is_empty() || bundle.rules.len() > 256 {
        return Err("policy must contain between one and 256 rules".to_string());
    }
    let mut ids = HashSet::new();
    for rule in &bundle.rules {
        if !bounded(&rule.rule_id)
            || !ids.insert(rule.rule_id.as_str())
            || !selector_valid(&rule.actions)
            || !unique(&rule.actions)
            || (!selector_valid(&rule.subjects.agent_ids)
                && !selector_valid(&rule.subjects.identity_ids))
            || (!selector_valid(&rule.resources.resource_types)
                && !selector_valid(&rule.resources.resource_ids))
            || !optional_selector_valid(&rule.subjects.agent_ids)
            || !optional_selector_valid(&rule.subjects.identity_ids)
            || !optional_selector_valid(&rule.subjects.tenant_ids)
            || !optional_selector_valid(&rule.resources.resource_types)
            || !optional_selector_valid(&rule.resources.resource_ids)
            || !optional_selector_valid(&rule.resources.tenant_ids)
            || !optional_selector_valid(&rule.conditions.required_capabilities)
            || !optional_selector_valid(&rule.conditions.required_purposes)
            || !optional_selector_valid(&rule.conditions.required_approval_roles)
            || !unique(&rule.subjects.agent_ids)
            || !unique(&rule.subjects.identity_ids)
            || !unique(&rule.subjects.tenant_ids)
            || !unique(&rule.resources.resource_types)
            || !unique(&rule.resources.resource_ids)
            || !unique(&rule.resources.tenant_ids)
            || !unique(&rule.conditions.required_capabilities)
            || !unique(&rule.conditions.required_purposes)
            || !unique(&rule.conditions.required_approval_roles)
            || rule
                .conditions
                .required_provenance
                .as_deref()
                .map(|value| !bounded(value))
                .unwrap_or(false)
        {
            return Err("policy rule identity or selectors are invalid".to_string());
        }
        if matches!(rule.effect, PolicyEffect::Allow)
            && rule.subjects.agent_ids.iter().any(|value| value == "*")
            && rule.subjects.identity_ids.iter().any(|value| value == "*")
        {
            return Err("allow rules must bind a concrete agent or identity".to_string());
        }
        if matches!(rule.effect, PolicyEffect::Allow)
            && rule.conditions.required_capabilities.is_empty()
            && rule.conditions.required_approval_roles.is_empty()
        {
            return Err("allow rules require a capability or explicit approval".to_string());
        }
    }
    Ok(())
}

fn validate_request(request: &AuthorityRequest) -> Result<(), String> {
    let values = [
        request.request_id.as_str(),
        request.subject.agent_id.as_str(),
        request.subject.identity_id.as_str(),
        request.subject.tenant_id.as_str(),
        request.delegation.delegated_by.as_str(),
        request.delegation.purpose.as_str(),
        request.action.as_str(),
        request.resource.resource_type.as_str(),
        request.resource.resource_id.as_str(),
        request.resource.tenant_id.as_str(),
        request.context.provenance.as_str(),
    ];
    if request.schema_version != REQUEST_VERSION
        || values.iter().any(|value| !bounded(value))
        || !optional_selector_valid(&request.delegation.capability_ids)
        || !optional_selector_valid(&request.context.approval_roles)
        || !unique(&request.delegation.capability_ids)
        || !unique(&request.context.approval_roles)
        || !(0.0..=1.0).contains(&request.context.risk_score)
    {
        return Err("authority request is invalid".to_string());
    }
    Ok(())
}

fn rule_selector_matches(rule: &PolicyRule, request: &AuthorityRequest) -> bool {
    (rule.subjects.agent_ids.is_empty()
        || selector_matches(&rule.subjects.agent_ids, &request.subject.agent_id))
        && (rule.subjects.identity_ids.is_empty()
            || selector_matches(&rule.subjects.identity_ids, &request.subject.identity_id))
        && (rule.subjects.tenant_ids.is_empty()
            || selector_matches(&rule.subjects.tenant_ids, &request.subject.tenant_id))
        && selector_matches(&rule.actions, &request.action)
        && (rule.resources.resource_types.is_empty()
            || selector_matches(
                &rule.resources.resource_types,
                &request.resource.resource_type,
            ))
        && (rule.resources.resource_ids.is_empty()
            || selector_matches(&rule.resources.resource_ids, &request.resource.resource_id))
        && (rule.resources.tenant_ids.is_empty()
            || selector_matches(&rule.resources.tenant_ids, &request.resource.tenant_id))
}

fn rule_conditions_match(rule: &PolicyRule, request: &AuthorityRequest) -> bool {
    contains_all(
        &request.delegation.capability_ids,
        &rule.conditions.required_capabilities,
    ) && (rule.conditions.required_purposes.is_empty()
        || selector_matches(
            &rule.conditions.required_purposes,
            &request.delegation.purpose,
        ))
        && rule
            .conditions
            .required_provenance
            .as_ref()
            .map(|value| value == &request.context.provenance)
            .unwrap_or(true)
        && rule
            .conditions
            .max_delegation_depth
            .map(|depth| request.delegation.depth <= depth)
            .unwrap_or(true)
        && (!rule.conditions.require_resource_tenant_match
            || request.subject.tenant_id == request.resource.tenant_id)
}

fn policy_digest(bundle: &PolicyBundle) -> Result<String, String> {
    let bytes = serde_json::to_vec(bundle)
        .map_err(|error| format!("failed to serialize Guard policy: {error}"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn privilege_expansion_action(action: &str) -> bool {
    matches!(
        action,
        "identity.grant"
            | "identity.assume"
            | "capability.issue"
            | "capability.delegate"
            | "policy.allow"
            | "policy.expand"
    )
}

fn guard_tampering_action(action: &str) -> bool {
    matches!(
        action,
        "guard.disable" | "guard.policy.delete" | "guard.telemetry.clear"
    )
}

struct DecisionOutcome {
    effect: PolicyEffect,
    source: &'static str,
    matched_rule_ids: Vec<String>,
    reason_codes: Vec<String>,
    adaptive: bool,
}

fn decision(
    bundle: &PolicyBundle,
    request: &AuthorityRequest,
    digest: String,
    outcome: DecisionOutcome,
) -> PolicyDecision {
    PolicyDecision {
        schema_version: DECISION_VERSION,
        request_id: request.request_id.clone(),
        policy_id: bundle.policy_id.clone(),
        policy_revision: bundle.revision,
        policy_digest: digest,
        effect: outcome.effect,
        decision_source: outcome.source.to_string(),
        matched_rule_ids: outcome.matched_rule_ids,
        reason_codes: outcome.reason_codes,
        adaptive_tightening_applied: outcome.adaptive,
        authority_expanded: false,
    }
}

pub fn evaluate_policy(
    bundle: &PolicyBundle,
    request: &AuthorityRequest,
) -> Result<PolicyDecision, String> {
    validate_policy_bundle(bundle)?;
    validate_request(request)?;
    let digest = policy_digest(bundle)?;
    if request.subject.tenant_id != request.resource.tenant_id {
        return Ok(decision(
            bundle,
            request,
            digest,
            DecisionOutcome {
                effect: PolicyEffect::Deny,
                source: "fixed_invariant",
                matched_rule_ids: vec![],
                reason_codes: vec!["fixed:cross_tenant_denied".to_string()],
                adaptive: false,
            },
        ));
    }
    if !request.delegation.signature_verified
        || request.delegation.expires_at <= request.context.observed_at
    {
        return Ok(decision(
            bundle,
            request,
            digest,
            DecisionOutcome {
                effect: PolicyEffect::Deny,
                source: "fixed_invariant",
                matched_rule_ids: vec![],
                reason_codes: vec!["fixed:delegation_invalid".to_string()],
                adaptive: false,
            },
        ));
    }
    if guard_tampering_action(&request.action) {
        return Ok(decision(
            bundle,
            request,
            digest,
            DecisionOutcome {
                effect: PolicyEffect::Deny,
                source: "fixed_invariant",
                matched_rule_ids: vec![],
                reason_codes: vec!["fixed:guard_tampering_denied".to_string()],
                adaptive: false,
            },
        ));
    }
    if privilege_expansion_action(&request.action)
        && (request.context.provenance != "verified"
            || !contains_all(
                &request.context.approval_roles,
                &["security".to_string(), "agent_owner".to_string()],
            ))
    {
        return Ok(decision(
            bundle,
            request,
            digest,
            DecisionOutcome {
                effect: PolicyEffect::Deny,
                source: "fixed_invariant",
                matched_rule_ids: vec![],
                reason_codes: vec!["fixed:untrusted_privilege_expansion_denied".to_string()],
                adaptive: false,
            },
        ));
    }
    if request.context.risk_score >= bundle.adaptive.block_risk_threshold {
        return Ok(decision(
            bundle,
            request,
            digest,
            DecisionOutcome {
                effect: PolicyEffect::Deny,
                source: "adaptive",
                matched_rule_ids: vec![],
                reason_codes: vec!["adaptive:risk_block_threshold".to_string()],
                adaptive: true,
            },
        ));
    }

    let mut rules = bundle
        .rules
        .iter()
        .filter(|rule| rule_selector_matches(rule, request))
        .collect::<Vec<_>>();
    rules.sort_by_key(|rule| (rule.priority, rule.rule_id.as_str()));
    let mut matched = Vec::new();
    let mut approval_missing = false;
    let mut selected: Option<PolicyEffect> = None;
    for rule in rules {
        if !rule_conditions_match(rule, request) {
            continue;
        }
        matched.push(rule.rule_id.clone());
        if !contains_all(
            &request.context.approval_roles,
            &rule.conditions.required_approval_roles,
        ) {
            approval_missing = true;
            continue;
        }
        match rule.effect {
            PolicyEffect::Deny => {
                selected = Some(PolicyEffect::Deny);
                break;
            }
            PolicyEffect::RequireApproval => selected = Some(PolicyEffect::RequireApproval),
            PolicyEffect::Allow if selected.is_none() => selected = Some(PolicyEffect::Allow),
            PolicyEffect::Allow => {}
        }
    }
    let (mut effect, mut source, mut reasons) = if matches!(selected, Some(PolicyEffect::Deny)) {
        (
            PolicyEffect::Deny,
            "rule",
            vec!["policy:explicit_deny".to_string()],
        )
    } else if approval_missing || matches!(selected, Some(PolicyEffect::RequireApproval)) {
        (
            PolicyEffect::RequireApproval,
            "rule",
            vec!["policy:approval_required".to_string()],
        )
    } else if matches!(selected, Some(PolicyEffect::Allow)) {
        (
            PolicyEffect::Allow,
            "rule",
            vec!["policy:least_privilege_allow".to_string()],
        )
    } else {
        (
            bundle.default_effect,
            "default",
            vec!["policy:default_effect".to_string()],
        )
    };
    let mut adaptive = false;
    if request.context.risk_score >= bundle.adaptive.review_risk_threshold
        && matches!(effect, PolicyEffect::Allow)
    {
        effect = PolicyEffect::RequireApproval;
        source = "adaptive";
        reasons.push("adaptive:risk_review_threshold".to_string());
        adaptive = true;
    }
    Ok(decision(
        bundle,
        request,
        digest,
        DecisionOutcome {
            effect,
            source,
            matched_rule_ids: matched,
            reason_codes: reasons,
            adaptive,
        },
    ))
}

pub fn evaluate_policy_json(input: &str) -> Result<String, String> {
    let parsed = serde_json::from_str::<PolicyEvaluateInput>(input)
        .map_err(|error| format!("invalid policy-evaluate payload: {error}"))?;
    let result = evaluate_policy(&parsed.policy_bundle, &parsed.request)?;
    serde_json::to_string(&result)
        .map_err(|error| format!("failed to serialize policy decision: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: POLICY_VERSION.to_string(),
            policy_id: "policy/case-delete".to_string(),
            revision: 1,
            default_effect: PolicyEffect::Deny,
            invariants: PolicyInvariants {
                deny_cross_tenant: true,
                deny_untrusted_privilege_expansion: true,
                deny_guard_tampering: true,
                require_signed_delegation: true,
            },
            rules: vec![PolicyRule {
                rule_id: "allow-case-delete".to_string(),
                priority: 100,
                effect: PolicyEffect::Allow,
                subjects: SubjectSelector {
                    agent_ids: vec!["law-agent".to_string()],
                    identity_ids: vec!["service/law-agent".to_string()],
                    tenant_ids: vec!["tenant/acme".to_string()],
                },
                actions: vec!["case.delete".to_string()],
                resources: ResourceSelector {
                    resource_types: vec!["case".to_string()],
                    resource_ids: vec!["*".to_string()],
                    tenant_ids: vec!["tenant/acme".to_string()],
                },
                conditions: PolicyConditions {
                    required_capabilities: vec!["case.delete".to_string()],
                    required_purposes: vec!["retention".to_string()],
                    required_provenance: Some("verified".to_string()),
                    required_approval_roles: vec!["case_owner".to_string()],
                    max_delegation_depth: Some(1),
                    require_resource_tenant_match: true,
                },
                immutable: false,
            }],
            adaptive: AdaptivePolicy {
                mode: "tightening_only".to_string(),
                review_risk_threshold: 0.6,
                block_risk_threshold: 0.9,
                allowed_automatic_effects: vec![PolicyEffect::Deny, PolicyEffect::RequireApproval],
                authority_expansion: "human_approval_required".to_string(),
            },
        }
    }

    fn request() -> AuthorityRequest {
        AuthorityRequest {
            schema_version: REQUEST_VERSION.to_string(),
            request_id: "request/1".to_string(),
            subject: AuthoritySubject {
                agent_id: "law-agent".to_string(),
                identity_id: "service/law-agent".to_string(),
                tenant_id: "tenant/acme".to_string(),
            },
            delegation: AuthorityDelegation {
                delegated_by: "user/case-owner".to_string(),
                capability_ids: vec!["case.delete".to_string()],
                purpose: "retention".to_string(),
                depth: 1,
                expires_at: 2_000,
                signature_verified: true,
            },
            action: "case.delete".to_string(),
            resource: AuthorityResource {
                resource_type: "case".to_string(),
                resource_id: "case/123".to_string(),
                tenant_id: "tenant/acme".to_string(),
            },
            context: AuthorityContext {
                provenance: "verified".to_string(),
                risk_score: 0.1,
                approval_roles: vec!["case_owner".to_string()],
                observed_at: 1_000,
            },
        }
    }

    #[test]
    fn allows_exact_identity_capability_and_approval() {
        let result = evaluate_policy(&bundle(), &request()).unwrap();
        assert_eq!(result.effect, PolicyEffect::Allow);
        assert_eq!(result.matched_rule_ids, vec!["allow-case-delete"]);
        assert!(!result.authority_expanded);
    }

    #[test]
    fn fixed_invariant_denies_cross_tenant_even_when_rule_allows() {
        let mut input = request();
        input.resource.tenant_id = "tenant/other".to_string();
        let result = evaluate_policy(&bundle(), &input).unwrap();
        assert_eq!(result.effect, PolicyEffect::Deny);
        assert_eq!(result.decision_source, "fixed_invariant");
    }

    #[test]
    fn adaptive_policy_can_tighten_but_never_expand() {
        let mut input = request();
        input.context.risk_score = 0.7;
        let result = evaluate_policy(&bundle(), &input).unwrap();
        assert_eq!(result.effect, PolicyEffect::RequireApproval);
        assert!(result.adaptive_tightening_applied);
        let mut invalid = bundle();
        invalid.adaptive.allowed_automatic_effects = vec![PolicyEffect::Allow];
        assert!(validate_policy_bundle(&invalid).is_err());
    }

    #[test]
    fn rejects_malformed_optional_selectors_and_duplicate_authority() {
        let mut invalid_policy = bundle();
        invalid_policy.rules[0].subjects.identity_ids = vec!["bad\nidentity".to_string()];
        assert!(validate_policy_bundle(&invalid_policy).is_err());

        let mut invalid_request = request();
        invalid_request.delegation.capability_ids =
            vec!["case.delete".to_string(), "case.delete".to_string()];
        assert!(evaluate_policy(&bundle(), &invalid_request).is_err());
    }
}
