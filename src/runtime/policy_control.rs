use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::atomic_store;
use super::contracts::{PolicyMutationRequest, RolloutObservationRequest};
use super::crypto;
use crate::policy::{
    self, AdaptivePolicy, AuthorityRequest, PolicyBundle, PolicyEffect, PolicyInvariants,
    PolicyRule,
};

pub const POLICY_V2: &str = "armorer-guard-policy-bundle/v2";
pub const POLICY_SET_V1: &str = "armorer-guard-active-policy-set/v1";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    Organization,
    Tenant,
    Agent,
    Adaptive,
}

impl PolicyLayer {
    fn directory(self) -> &'static str {
        match self {
            Self::Organization => "organization",
            Self::Tenant => "tenant",
            Self::Agent => "agent",
            Self::Adaptive => "adaptive",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyScopeV2 {
    #[serde(default)]
    pub tenant_ids: Vec<String>,
    #[serde(default)]
    pub agent_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignatureV2 {
    pub key_id: String,
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivationV2 {
    pub mode: String,
    #[serde(default)]
    pub canary_percent: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundleV2 {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: u64,
    #[serde(default)]
    pub previous_revision: Option<u64>,
    pub layer: PolicyLayer,
    pub scope: PolicyScopeV2,
    pub default_effect: PolicyEffect,
    pub rules: Vec<PolicyRule>,
    pub adaptive: AdaptivePolicy,
    pub proposed_by: String,
    pub proposed_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub activation: PolicyActivationV2,
    pub signatures: Vec<PolicySignatureV2>,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    schema_version: &'a str,
    policy_id: &'a str,
    revision: u64,
    previous_revision: Option<u64>,
    layer: PolicyLayer,
    scope: &'a PolicyScopeV2,
    default_effect: PolicyEffect,
    rules: &'a [PolicyRule],
    adaptive: &'a AdaptivePolicy,
    proposed_by: &'a str,
    proposed_at: u64,
    expires_at: Option<u64>,
    activation: &'a PolicyActivationV2,
}

impl SignedPolicyBundleV2 {
    fn signing_payload(&self) -> SigningPayload<'_> {
        SigningPayload {
            schema_version: &self.schema_version,
            policy_id: &self.policy_id,
            revision: self.revision,
            previous_revision: self.previous_revision,
            layer: self.layer,
            scope: &self.scope,
            default_effect: self.default_effect,
            rules: &self.rules,
            adaptive: &self.adaptive,
            proposed_by: &self.proposed_by,
            proposed_at: self.proposed_at,
            expires_at: self.expires_at,
            activation: &self.activation,
        }
    }

    pub fn digest(&self) -> Result<String, String> {
        crypto::digest(&self.signing_payload())
    }

    pub fn sign(&mut self, key_id: &str, key: &[u8]) -> Result<(), String> {
        let value = crypto::sign(key, &self.signing_payload())?;
        self.signatures = vec![PolicySignatureV2 {
            key_id: key_id.to_string(),
            algorithm: "hmac-sha256".to_string(),
            value,
        }];
        Ok(())
    }

    fn compile(&self) -> PolicyBundle {
        PolicyBundle {
            schema_version: "armorer-guard-policy-bundle/v1".to_string(),
            policy_id: self.policy_id.clone(),
            revision: self.revision,
            default_effect: self.default_effect,
            invariants: fixed_invariants(),
            rules: self.rules.clone(),
            adaptive: self.adaptive.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePolicySet {
    pub schema_version: String,
    pub activated_at: u64,
    pub layers: BTreeMap<PolicyLayer, SignedPolicyBundleV2>,
    pub digests: BTreeMap<PolicyLayer, String>,
    #[serde(default)]
    pub staged: BTreeMap<PolicyLayer, SignedPolicyBundleV2>,
    #[serde(default)]
    pub staged_digests: BTreeMap<PolicyLayer, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyHistoryEntry {
    pub policy_id: String,
    pub revision: u64,
    pub previous_revision: Option<u64>,
    pub layer: PolicyLayer,
    pub digest: String,
    pub activation_mode: String,
    pub active: bool,
    pub staged: bool,
}

pub struct PolicyControlPlane {
    root: PathBuf,
    signer_key_id: String,
    verifier_key: Vec<u8>,
    active: ActivePolicySet,
}

impl PolicyControlPlane {
    pub fn load(
        root: PathBuf,
        signer_key_id: String,
        verifier_key: Vec<u8>,
        bootstrap: Option<PolicyBundle>,
        observed_at: u64,
    ) -> Result<Self, String> {
        if verifier_key.len() < 32 {
            return Err("policy verifier key must contain at least 32 bytes".to_string());
        }
        fs::create_dir_all(root.join("revisions"))
            .map_err(|error| format!("failed to create policy store: {error}"))?;
        let active_path = root.join("active.json");
        let active = if let Some(active) = atomic_store::read_json::<ActivePolicySet>(&active_path)?
        {
            validate_active_set(&active, &signer_key_id, &verifier_key, observed_at)?;
            active
        } else {
            let mut active = ActivePolicySet {
                schema_version: POLICY_SET_V1.to_string(),
                activated_at: observed_at,
                layers: BTreeMap::new(),
                digests: BTreeMap::new(),
                staged: BTreeMap::new(),
                staged_digests: BTreeMap::new(),
            };
            if let Some(bundle) = bootstrap {
                policy::validate_policy_bundle(&bundle)?;
                let mut revision = SignedPolicyBundleV2 {
                    schema_version: POLICY_V2.to_string(),
                    policy_id: bundle.policy_id,
                    revision: bundle.revision,
                    previous_revision: None,
                    layer: PolicyLayer::Organization,
                    scope: PolicyScopeV2 {
                        tenant_ids: Vec::new(),
                        agent_ids: Vec::new(),
                    },
                    default_effect: bundle.default_effect,
                    rules: bundle.rules,
                    adaptive: bundle.adaptive,
                    proposed_by: "operator/local-bootstrap".to_string(),
                    proposed_at: observed_at,
                    expires_at: None,
                    activation: PolicyActivationV2 {
                        mode: "enforced".to_string(),
                        canary_percent: None,
                    },
                    signatures: Vec::new(),
                };
                revision.sign(&signer_key_id, &verifier_key)?;
                let digest = revision.digest()?;
                active.digests.insert(revision.layer, digest);
                active.layers.insert(revision.layer, revision);
                atomic_store::atomic_json(&active_path, &active)?;
            }
            active
        };
        Ok(Self {
            root,
            signer_key_id,
            verifier_key,
            active,
        })
    }

    pub fn ready(&self) -> bool {
        !self.active.layers.is_empty()
    }

    pub fn effective_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.active)
            .map_err(|error| format!("failed to serialize active policy set: {error}"))
    }

    pub fn effective_revision(&self) -> Option<u64> {
        self.active
            .layers
            .values()
            .map(|policy| policy.revision)
            .max()
    }

    pub fn authorize_mutation(&self, request: &PolicyMutationRequest) -> Result<(), String> {
        #[derive(Serialize)]
        struct Authorization<'a> {
            operation: &'a str,
            layer: PolicyLayer,
            revision: u64,
            observed_at: u64,
            expires_at: u64,
            approver_id: &'a str,
            approver_role: &'a str,
            simulation_receipt_ids: &'a [String],
        }
        if !matches!(request.operation.as_str(), "activate" | "rollback")
            || request.revision == 0
            || request.approver_id.trim().is_empty()
            || !matches!(
                request.approver_role.as_str(),
                "security" | "policy_approver"
            )
            || request.expires_at <= request.observed_at
            || request.expires_at > request.observed_at.saturating_add(300)
            || (request.operation == "activate" && request.simulation_receipt_ids.is_empty())
            || request
                .simulation_receipt_ids
                .iter()
                .any(|id| id.trim().is_empty())
        {
            return Err("policy mutation authorization metadata is invalid".to_string());
        }
        let authorization = Authorization {
            operation: &request.operation,
            layer: request.layer,
            revision: request.revision,
            observed_at: request.observed_at,
            expires_at: request.expires_at,
            approver_id: &request.approver_id,
            approver_role: &request.approver_role,
            simulation_receipt_ids: &request.simulation_receipt_ids,
        };
        if !crypto::verify(&self.verifier_key, &authorization, &request.signature) {
            return Err("policy mutation authorization signature is invalid".to_string());
        }
        Ok(())
    }

    pub fn propose(
        &self,
        bundle: &SignedPolicyBundleV2,
        observed_at: u64,
    ) -> Result<String, String> {
        self.validate_revision(bundle, observed_at, true)?;
        let digest = bundle.digest()?;
        let path = self.revision_path(bundle.layer, bundle.revision, &digest);
        if path.exists() {
            let existing: SignedPolicyBundleV2 = atomic_store::read_json(&path)?
                .ok_or_else(|| "policy revision disappeared during proposal".to_string())?;
            if existing.digest()? != digest {
                return Err("policy revision conflicts with an existing digest".to_string());
            }
            return Ok(digest);
        }
        atomic_store::atomic_json(&path, bundle)?;
        atomic_store::append_json(
            &self.root.join("history.jsonl"),
            &serde_json::json!({
                "event": "proposed",
                "layer": bundle.layer,
                "revision": bundle.revision,
                "digest": digest,
                "observed_at": observed_at,
                "proposed_by": bundle.proposed_by,
            }),
        )?;
        Ok(digest)
    }

    pub fn activate(
        &mut self,
        layer: PolicyLayer,
        revision: u64,
        observed_at: u64,
    ) -> Result<String, String> {
        let bundle = self.find_revision(layer, revision)?;
        self.validate_revision(&bundle, observed_at, true)?;
        if bundle.activation.mode == "proposed" {
            return Err(
                "a proposed policy must be signed for shadow, canary, or enforced activation"
                    .to_string(),
            );
        }
        let digest = bundle.digest()?;
        let mut candidate = self.active.clone();
        candidate.activated_at = observed_at;
        if matches!(bundle.activation.mode.as_str(), "shadow" | "canary") {
            candidate.staged.insert(layer, bundle.clone());
            candidate.staged_digests.insert(layer, digest.clone());
        } else {
            candidate.layers.insert(layer, bundle.clone());
            candidate.digests.insert(layer, digest.clone());
            candidate.staged.remove(&layer);
            candidate.staged_digests.remove(&layer);
        }
        validate_active_set(
            &candidate,
            &self.signer_key_id,
            &self.verifier_key,
            observed_at,
        )?;
        atomic_store::atomic_json(&self.root.join("active.json"), &candidate)?;
        self.active = candidate;
        atomic_store::append_json(
            &self.root.join("history.jsonl"),
            &serde_json::json!({
                "event": if matches!(bundle.activation.mode.as_str(), "shadow" | "canary") {
                    "staged"
                } else {
                    "activated"
                },
                "layer": layer,
                "revision": revision,
                "digest": digest,
                "observed_at": observed_at,
            }),
        )?;
        Ok(digest)
    }

    pub fn observe_rollout(
        &mut self,
        request: &RolloutObservationRequest,
    ) -> Result<String, String> {
        if !request.attack_prevention_regression.is_finite()
            || !request.utility_regression.is_finite()
            || !(0.0..=1.0).contains(&request.maximum_attack_regression)
            || !(0.0..=1.0).contains(&request.maximum_utility_regression)
            || request.sample_count == 0
        {
            return Err("rollout observation metrics are invalid".to_string());
        }
        let staged = self
            .active
            .staged
            .get(&request.layer)
            .filter(|bundle| bundle.revision == request.revision)
            .cloned()
            .ok_or_else(|| "staged rollout revision was not found".to_string())?;
        let regressed = request.attack_prevention_regression > request.maximum_attack_regression
            || request.utility_regression > request.maximum_utility_regression;
        let status = if regressed {
            self.active.staged.remove(&request.layer);
            self.active.staged_digests.remove(&request.layer);
            "automatically_rolled_back"
        } else {
            "observing"
        };
        self.active.activated_at = request.observed_at;
        validate_active_set(
            &self.active,
            &self.signer_key_id,
            &self.verifier_key,
            request.observed_at,
        )?;
        atomic_store::atomic_json(&self.root.join("active.json"), &self.active)?;
        atomic_store::append_json(
            &self.root.join("history.jsonl"),
            &serde_json::json!({
                "event": status,
                "layer": request.layer,
                "revision": request.revision,
                "digest": staged.digest()?,
                "attack_prevention_regression": request.attack_prevention_regression,
                "utility_regression": request.utility_regression,
                "sample_count": request.sample_count,
                "observed_at": request.observed_at,
            }),
        )?;
        Ok(status.to_string())
    }

    pub fn authorize_rollout_observation(
        &self,
        request: &RolloutObservationRequest,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        struct Authorization<'a> {
            layer: PolicyLayer,
            revision: u64,
            attack_prevention_regression: f64,
            utility_regression: f64,
            sample_count: u64,
            maximum_attack_regression: f64,
            maximum_utility_regression: f64,
            observed_at: u64,
            expires_at: u64,
            observer_id: &'a str,
            observer_role: &'a str,
        }
        if request.observer_id.trim().is_empty()
            || !matches!(
                request.observer_role.as_str(),
                "security" | "rollout_observer"
            )
            || request.expires_at <= request.observed_at
            || request.expires_at > request.observed_at.saturating_add(300)
        {
            return Err("rollout observation authorization metadata is invalid".to_string());
        }
        let authorization = Authorization {
            layer: request.layer,
            revision: request.revision,
            attack_prevention_regression: request.attack_prevention_regression,
            utility_regression: request.utility_regression,
            sample_count: request.sample_count,
            maximum_attack_regression: request.maximum_attack_regression,
            maximum_utility_regression: request.maximum_utility_regression,
            observed_at: request.observed_at,
            expires_at: request.expires_at,
            observer_id: &request.observer_id,
            observer_role: &request.observer_role,
        };
        if !crypto::verify(&self.verifier_key, &authorization, &request.signature) {
            return Err("rollout observation authorization signature is invalid".to_string());
        }
        Ok(())
    }

    pub fn rollback(
        &mut self,
        layer: PolicyLayer,
        revision: u64,
        observed_at: u64,
    ) -> Result<String, String> {
        let current_revision = self
            .active
            .layers
            .get(&layer)
            .ok_or_else(|| format!("no active {} policy exists", layer.directory()))?;
        let current_revision = current_revision.revision;
        if revision >= current_revision {
            return Err("rollback revision must precede the active revision".to_string());
        }
        let digest = self.activate(layer, revision, observed_at)?;
        atomic_store::append_json(
            &self.root.join("history.jsonl"),
            &serde_json::json!({
                "event": "rolled_back",
                "layer": layer,
                "from_revision": current_revision,
                "to_revision": revision,
                "digest": digest,
                "observed_at": observed_at,
            }),
        )?;
        Ok(digest)
    }

    pub fn history(&self) -> Result<Vec<PolicyHistoryEntry>, String> {
        let mut entries = Vec::new();
        let revisions_root = self.root.join("revisions");
        for layer in [
            PolicyLayer::Organization,
            PolicyLayer::Tenant,
            PolicyLayer::Agent,
            PolicyLayer::Adaptive,
        ] {
            let directory = revisions_root.join(layer.directory());
            let Ok(files) = fs::read_dir(directory) else {
                continue;
            };
            for file in files {
                let path = file
                    .map_err(|error| format!("failed to read policy history: {error}"))?
                    .path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let bundle: SignedPolicyBundleV2 = atomic_store::read_json(&path)?
                    .ok_or_else(|| "policy history entry disappeared".to_string())?;
                entries.push(PolicyHistoryEntry {
                    policy_id: bundle.policy_id.clone(),
                    revision: bundle.revision,
                    previous_revision: bundle.previous_revision,
                    layer,
                    digest: bundle.digest()?,
                    activation_mode: bundle.activation.mode,
                    active: self
                        .active
                        .layers
                        .get(&layer)
                        .is_some_and(|active| active.revision == bundle.revision),
                    staged: self
                        .active
                        .staged
                        .get(&layer)
                        .is_some_and(|staged| staged.revision == bundle.revision),
                });
            }
        }
        entries.sort_by_key(|entry| (entry.layer, entry.revision));
        Ok(entries)
    }

    pub fn effective_for(
        &self,
        tenant_id: &str,
        agent_id: &str,
        observed_at: u64,
    ) -> Result<PolicyBundle, String> {
        let mut matched = self
            .active
            .layers
            .values()
            .filter(|bundle| scope_matches(&bundle.scope, tenant_id, agent_id))
            .filter(|bundle| bundle.expires_at.is_none_or(|expiry| expiry > observed_at))
            .collect::<Vec<_>>();
        matched.sort_by_key(|bundle| bundle.layer);
        if matched.is_empty() {
            return Err("no active policy matches the subject scope".to_string());
        }
        let mut rules = Vec::new();
        let mut ids = Vec::new();
        let mut revision = 0;
        let mut review_threshold: f64 = 1.0;
        let mut block_threshold: f64 = 1.0;
        for bundle in matched {
            rules.extend(bundle.rules.clone());
            ids.push(format!("{}@{}", bundle.policy_id, bundle.revision));
            revision = revision.max(bundle.revision);
            review_threshold = review_threshold.min(bundle.adaptive.review_risk_threshold);
            block_threshold = block_threshold.min(bundle.adaptive.block_risk_threshold);
        }
        let compiled = PolicyBundle {
            schema_version: "armorer-guard-policy-bundle/v1".to_string(),
            policy_id: format!("effective/{}", ids.join("+")),
            revision,
            default_effect: PolicyEffect::Deny,
            invariants: fixed_invariants(),
            rules,
            adaptive: AdaptivePolicy {
                mode: "tightening_only".to_string(),
                review_risk_threshold: review_threshold,
                block_risk_threshold: block_threshold.max(review_threshold),
                allowed_automatic_effects: vec![PolicyEffect::Deny, PolicyEffect::RequireApproval],
                authority_expansion: "human_approval_required".to_string(),
            },
        };
        policy::validate_policy_bundle(&compiled)?;
        Ok(compiled)
    }

    pub fn simulate(
        &self,
        bundle: &SignedPolicyBundleV2,
        requests: &[AuthorityRequest],
        observed_at: u64,
    ) -> Result<Vec<policy::PolicyDecision>, String> {
        self.validate_revision(bundle, observed_at, false)?;
        let compiled = bundle.compile();
        requests
            .iter()
            .map(|request| policy::evaluate_policy(&compiled, request))
            .collect()
    }

    fn validate_revision(
        &self,
        bundle: &SignedPolicyBundleV2,
        observed_at: u64,
        require_chain: bool,
    ) -> Result<(), String> {
        validate_revision_shape(bundle, observed_at)?;
        let signature = bundle
            .signatures
            .iter()
            .find(|signature| {
                signature.key_id == self.signer_key_id && signature.algorithm == "hmac-sha256"
            })
            .ok_or_else(|| "policy lacks an authorized signature".to_string())?;
        if !crypto::verify(
            &self.verifier_key,
            &bundle.signing_payload(),
            &signature.value,
        ) {
            return Err("policy signature verification failed".to_string());
        }
        if require_chain {
            let active = self.active.layers.get(&bundle.layer);
            match active {
                Some(active)
                    if bundle.revision > active.revision
                        && bundle.previous_revision != Some(active.revision) =>
                {
                    return Err(
                        "policy previous_revision does not match active revision".to_string()
                    );
                }
                Some(active)
                    if bundle.revision == active.revision
                        && bundle.digest()? != active.digest()? =>
                {
                    return Err("active policy revision digest is immutable".to_string());
                }
                Some(_) => {}
                None if bundle.previous_revision.is_some() => {
                    return Err("first layer revision may not name a predecessor".to_string())
                }
                None => {}
            }
        }
        Ok(())
    }

    fn find_revision(
        &self,
        layer: PolicyLayer,
        revision: u64,
    ) -> Result<SignedPolicyBundleV2, String> {
        let directory = self.root.join("revisions").join(layer.directory());
        let prefix = format!("{revision}-");
        let mut matches = fs::read_dir(&directory)
            .map_err(|error| format!("failed to read {}: {error}", directory.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".json"))
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "expected one signed policy for {} revision {revision}",
                layer.directory()
            ));
        }
        atomic_store::read_json(&matches.remove(0))?
            .ok_or_else(|| "policy revision disappeared".to_string())
    }

    fn revision_path(&self, layer: PolicyLayer, revision: u64, digest: &str) -> PathBuf {
        self.root
            .join("revisions")
            .join(layer.directory())
            .join(format!(
                "{revision}-{}.json",
                digest.trim_start_matches("sha256:")
            ))
    }
}

fn validate_active_set(
    active: &ActivePolicySet,
    key_id: &str,
    key: &[u8],
    observed_at: u64,
) -> Result<(), String> {
    if active.schema_version != POLICY_SET_V1 {
        return Err("unsupported active policy-set schema".to_string());
    }
    for (layer, bundle) in &active.layers {
        if layer != &bundle.layer {
            return Err("active policy layer key does not match its bundle".to_string());
        }
        validate_revision_shape(bundle, observed_at)?;
        let signature = bundle
            .signatures
            .iter()
            .find(|signature| signature.key_id == key_id && signature.algorithm == "hmac-sha256")
            .ok_or_else(|| "active policy lacks an authorized signature".to_string())?;
        if !crypto::verify(key, &bundle.signing_payload(), &signature.value) {
            return Err("active policy signature verification failed".to_string());
        }
        if active.digests.get(layer) != Some(&bundle.digest()?) {
            return Err("active policy digest does not match its snapshot".to_string());
        }
    }
    for (layer, bundle) in &active.staged {
        if layer != &bundle.layer || !matches!(bundle.activation.mode.as_str(), "shadow" | "canary")
        {
            return Err("staged policy metadata is invalid".to_string());
        }
        validate_revision_shape(bundle, observed_at)?;
        let signature = bundle
            .signatures
            .iter()
            .find(|signature| signature.key_id == key_id && signature.algorithm == "hmac-sha256")
            .ok_or_else(|| "staged policy lacks an authorized signature".to_string())?;
        if !crypto::verify(key, &bundle.signing_payload(), &signature.value)
            || active.staged_digests.get(layer) != Some(&bundle.digest()?)
        {
            return Err("staged policy signature or digest verification failed".to_string());
        }
    }
    Ok(())
}

fn validate_revision_shape(bundle: &SignedPolicyBundleV2, observed_at: u64) -> Result<(), String> {
    if bundle.schema_version != POLICY_V2
        || bundle.policy_id.trim().is_empty()
        || bundle.proposed_by.trim().is_empty()
        || bundle.revision == 0
        || !matches!(
            bundle.activation.mode.as_str(),
            "proposed" | "shadow" | "canary" | "enforced"
        )
        || bundle
            .activation
            .canary_percent
            .is_some_and(|percent| percent == 0 || percent > 100)
    {
        return Err("signed policy revision metadata is invalid".to_string());
    }
    if bundle.layer == PolicyLayer::Adaptive
        && (bundle
            .rules
            .iter()
            .any(|rule| rule.effect == PolicyEffect::Allow)
            || bundle.default_effect == PolicyEffect::Allow
            || bundle.expires_at.is_none())
    {
        return Err("adaptive policies must be expiring and tightening-only".to_string());
    }
    if bundle
        .expires_at
        .is_some_and(|expiry| expiry <= observed_at)
    {
        return Err("policy revision is expired".to_string());
    }
    let compiled = bundle.compile();
    policy::validate_policy_bundle(&compiled)
}

fn scope_matches(scope: &PolicyScopeV2, tenant_id: &str, agent_id: &str) -> bool {
    (scope.tenant_ids.is_empty() || scope.tenant_ids.iter().any(|value| value == tenant_id))
        && (scope.agent_ids.is_empty() || scope.agent_ids.iter().any(|value| value == agent_id))
}

fn fixed_invariants() -> PolicyInvariants {
    PolicyInvariants {
        deny_cross_tenant: true,
        deny_untrusted_privilege_expansion: true,
        deny_guard_tampering: true,
        require_signed_delegation: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(layer: PolicyLayer, revision: u64, previous: Option<u64>) -> SignedPolicyBundleV2 {
        let legacy: PolicyBundle = serde_json::from_value(serde_json::json!({
            "schema_version": "armorer-guard-policy-bundle/v1",
            "policy_id": "policy/test",
            "revision": revision,
            "default_effect": "deny",
            "invariants": {
                "deny_cross_tenant": true,
                "deny_untrusted_privilege_expansion": true,
                "deny_guard_tampering": true,
                "require_signed_delegation": true
            },
            "rules": [{
                "rule_id": "allow-read",
                "priority": 10,
                "effect": "allow",
                "subjects": {"agent_ids":["agent"],"identity_ids":["identity"],"tenant_ids":["tenant"]},
                "actions": ["record.read"],
                "resources": {"resource_types":["record"],"resource_ids":["*"],"tenant_ids":["tenant"]},
                "conditions": {"required_capabilities":["record.read"],"required_purposes":[],"required_approval_roles":[],"require_resource_tenant_match":true},
                "immutable": false
            }],
            "adaptive": {"mode":"tightening_only","review_risk_threshold":0.7,"block_risk_threshold":0.9,"allowed_automatic_effects":["deny","require_approval"],"authority_expansion":"human_approval_required"}
        })).unwrap();
        SignedPolicyBundleV2 {
            schema_version: POLICY_V2.to_string(),
            policy_id: format!("policy/{:?}", layer),
            revision,
            previous_revision: previous,
            layer,
            scope: PolicyScopeV2 {
                tenant_ids: vec!["tenant".to_string()],
                agent_ids: vec!["agent".to_string()],
            },
            default_effect: legacy.default_effect,
            rules: legacy.rules,
            adaptive: legacy.adaptive,
            proposed_by: "user/security".to_string(),
            proposed_at: 100,
            expires_at: (layer == PolicyLayer::Adaptive).then_some(1_000),
            activation: PolicyActivationV2 {
                mode: "enforced".to_string(),
                canary_percent: None,
            },
            signatures: Vec::new(),
        }
    }

    #[test]
    fn rejects_tampered_and_authority_expanding_adaptive_policy() {
        let key = [3; 32];
        let mut bundle = policy(PolicyLayer::Organization, 1, None);
        bundle.sign("key", &key).unwrap();
        assert!(crypto::verify(
            &key,
            &bundle.signing_payload(),
            &bundle.signatures[0].value
        ));
        bundle.rules[0].actions = vec!["record.delete".to_string()];
        assert!(!crypto::verify(
            &key,
            &bundle.signing_payload(),
            &bundle.signatures[0].value
        ));

        let mut adaptive = policy(PolicyLayer::Adaptive, 1, None);
        adaptive.sign("key", &key).unwrap();
        assert!(validate_revision_shape(&adaptive, 200).is_err());
    }

    #[test]
    fn activation_and_rollback_are_exact() {
        let root = std::env::temp_dir().join(format!(
            "guard-policy-control-test-{}",
            crypto::opaque_id("test", &[9; 32]).replace('/', "-")
        ));
        let mut control =
            PolicyControlPlane::load(root, "key".to_string(), vec![9; 32], None, 100).unwrap();
        let mut first = policy(PolicyLayer::Organization, 1, None);
        first.sign("key", &[9; 32]).unwrap();
        let first_digest = control.propose(&first, 100).unwrap();
        assert_eq!(
            control.activate(PolicyLayer::Organization, 1, 101).unwrap(),
            first_digest
        );

        let mut second = policy(PolicyLayer::Organization, 2, Some(1));
        second.sign("key", &[9; 32]).unwrap();
        control.propose(&second, 102).unwrap();
        control.activate(PolicyLayer::Organization, 2, 103).unwrap();
        assert_eq!(
            control.rollback(PolicyLayer::Organization, 1, 104).unwrap(),
            first_digest
        );
    }

    #[test]
    fn shadow_is_non_enforcing_and_regression_rolls_it_back() {
        let root = std::env::temp_dir().join(format!(
            "guard-policy-shadow-test-{}",
            crypto::opaque_id("test", &[6; 32]).replace('/', "-")
        ));
        let mut control =
            PolicyControlPlane::load(root, "key".to_string(), vec![6; 32], None, 100).unwrap();
        let mut enforced = policy(PolicyLayer::Organization, 1, None);
        enforced.sign("key", &[6; 32]).unwrap();
        control.propose(&enforced, 100).unwrap();
        control.activate(PolicyLayer::Organization, 1, 101).unwrap();
        let mut shadow = policy(PolicyLayer::Organization, 2, Some(1));
        shadow.activation.mode = "shadow".to_string();
        shadow.sign("key", &[6; 32]).unwrap();
        control.propose(&shadow, 102).unwrap();
        control.activate(PolicyLayer::Organization, 2, 103).unwrap();
        assert_eq!(control.effective_revision(), Some(1));
        assert_eq!(
            control.active.staged[&PolicyLayer::Organization].revision,
            2
        );
        assert_eq!(
            control
                .observe_rollout(&RolloutObservationRequest {
                    schema_version: super::super::contracts::ROLLOUT_OBSERVATION_VERSION
                        .to_string(),
                    layer: PolicyLayer::Organization,
                    revision: 2,
                    attack_prevention_regression: 0.0,
                    utility_regression: 0.2,
                    sample_count: 100,
                    maximum_attack_regression: 0.01,
                    maximum_utility_regression: 0.05,
                    observed_at: 104,
                    expires_at: 200,
                    observer_id: "telemetry/controller".to_string(),
                    observer_role: "rollout_observer".to_string(),
                    signature: "not-used-by-observe-unit".to_string(),
                })
                .unwrap(),
            "automatically_rolled_back"
        );
        assert!(control.active.staged.is_empty());
        assert_eq!(control.effective_revision(), Some(1));
    }

    #[test]
    fn control_plane_mutations_require_independent_signatures() {
        let root = std::env::temp_dir().join(format!(
            "guard-policy-auth-test-{}",
            crypto::opaque_id("test", &[8; 32]).replace('/', "-")
        ));
        let control =
            PolicyControlPlane::load(root, "key".to_string(), vec![8; 32], None, 100).unwrap();
        let request = PolicyMutationRequest {
            schema_version: super::super::contracts::POLICY_MUTATION_VERSION.to_string(),
            operation: "activate".to_string(),
            layer: PolicyLayer::Organization,
            revision: 1,
            observed_at: 100,
            expires_at: 200,
            approver_id: "user/security".to_string(),
            approver_role: "security".to_string(),
            simulation_receipt_ids: vec!["simulation-receipt/1".to_string()],
            signature: "hmac-sha256:invalid".to_string(),
        };
        assert!(control.authorize_mutation(&request).is_err());
    }
}
