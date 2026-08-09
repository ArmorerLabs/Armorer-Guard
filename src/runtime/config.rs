use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::crypto;
use super::enforcement::CapabilitySpec;

pub const MANIFEST_VERSION: &str = "armorer-guard-agent-manifest/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentManifest {
    pub schema_version: String,
    pub agent: AgentIdentity,
    pub transport: TransportConfig,
    pub policy: PolicyConfig,
    pub keys: KeyConfig,
    pub models: Vec<ModelRoute>,
    pub capabilities: Vec<CapabilitySpec>,
    pub destinations: Vec<DestinationConfig>,
    pub approvals: Vec<ApprovalRoute>,
    pub retention: RetentionConfig,
    pub adapters: Vec<AdapterConfig>,
    #[serde(default)]
    pub http_brokers: Vec<HttpBrokerConfig>,
    #[serde(default)]
    pub filesystem_brokers: Vec<FilesystemBrokerConfig>,
    #[serde(default)]
    pub protected_memory_keys: Vec<String>,
    #[serde(default)]
    pub declared_direct_routes: Vec<DirectRoute>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub workload_identity: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    pub kind: String,
    pub endpoint: String,
    #[serde(default)]
    pub server_certificate_file: Option<String>,
    #[serde(default)]
    pub server_private_key_file: Option<String>,
    #[serde(default)]
    pub client_ca_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub bootstrap_bundle: String,
    pub verifier_key_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    pub delegation_verifier_key_file: String,
    pub gateway_signing_key_file: String,
    pub approval_verifier_key_file: String,
    pub evidence_authorization_key_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    pub provider: String,
    pub model_id: String,
    pub regions: Vec<String>,
    pub allowed_data_classes: Vec<String>,
    pub retention: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationConfig {
    pub destination_id: String,
    pub tenant_id: String,
    pub allowed_data_classes: Vec<String>,
    pub require_approval: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRoute {
    pub capability_id: String,
    pub required_role: String,
    pub maximum_ttl_seconds: u64,
    pub maximum_usage_count: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    pub raw_evidence_seconds: u64,
    pub telemetry_seconds: u64,
    pub telemetry_max_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    pub kind: String,
    pub enabled: bool,
    pub fail_mode: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectRoute {
    pub capability_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBrokerConfig {
    pub capability_id: String,
    pub url_prefix: String,
    pub allowed_methods: Vec<String>,
    pub credential_header: String,
    pub credential_file: String,
    pub maximum_response_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemBrokerConfig {
    pub capability_id: String,
    pub root: String,
    pub allowed_operations: Vec<String>,
    pub maximum_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct CompiledManifest {
    pub schema_version: &'static str,
    pub manifest_digest: String,
    pub agent: AgentIdentity,
    pub capability_count: usize,
    pub destination_count: usize,
    pub adapter_count: usize,
    pub mediated_capabilities: Vec<String>,
    pub unenforced_capabilities: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn run_cli(args: &[String], explain: bool) -> Result<String, String> {
    let path = value(args, "--config")
        .map(PathBuf::from)
        .ok_or_else(|| "--config <manifest.json> is required".to_string())?;
    let manifest = load(&path)?;
    let compiled = compile(&manifest)?;
    if explain {
        let capability = value(args, "--capability");
        explain_manifest(&manifest, &compiled, capability.as_deref())
    } else {
        serde_json::to_string_pretty(&compiled)
            .map_err(|error| format!("failed to serialize validated manifest: {error}"))
    }
}

pub fn load(path: &Path) -> Result<AgentManifest, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read Guard agent manifest: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid Guard agent manifest: {error}"))
}

pub fn compile(manifest: &AgentManifest) -> Result<CompiledManifest, String> {
    validate(manifest)?;
    let mut mediated_capabilities = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.clone())
        .collect::<Vec<_>>();
    mediated_capabilities.sort();
    let mut unenforced_capabilities = manifest
        .declared_direct_routes
        .iter()
        .map(|route| format!("unenforced_capability/{}", route.capability_id))
        .collect::<Vec<_>>();
    unenforced_capabilities.sort();
    let warnings = manifest
        .adapters
        .iter()
        .filter(|adapter| !adapter.enabled)
        .map(|adapter| format!("adapter '{}' is disabled", adapter.kind))
        .collect();
    Ok(CompiledManifest {
        schema_version: "armorer-guard-compiled-manifest/v1",
        manifest_digest: crypto::digest(manifest)?,
        agent: manifest.agent.clone(),
        capability_count: manifest.capabilities.len(),
        destination_count: manifest.destinations.len(),
        adapter_count: manifest.adapters.len(),
        mediated_capabilities,
        unenforced_capabilities,
        warnings,
    })
}

fn validate(manifest: &AgentManifest) -> Result<(), String> {
    if manifest.schema_version != MANIFEST_VERSION {
        return Err("unsupported agent manifest schema".to_string());
    }
    if manifest.agent.agent_id.trim().is_empty()
        || manifest.agent.tenant_id.trim().is_empty()
        || !manifest.agent.workload_identity.starts_with("spiffe://")
    {
        return Err(
            "agent identity must include agent, tenant, and SPIFFE workload identity".into(),
        );
    }
    match manifest.transport.kind.as_str() {
        "unix_socket" => {
            if !Path::new(&manifest.transport.endpoint).is_absolute()
                || manifest.transport.server_certificate_file.is_some()
                || manifest.transport.server_private_key_file.is_some()
                || manifest.transport.client_ca_file.is_some()
            {
                return Err("Unix-socket transport requires only an absolute endpoint".into());
            }
        }
        "windows_named_pipe" => {
            if !manifest.transport.endpoint.starts_with(r"\\.\pipe\")
                || manifest.transport.server_certificate_file.is_some()
                || manifest.transport.server_private_key_file.is_some()
                || manifest.transport.client_ca_file.is_some()
            {
                return Err("Windows transport requires a \\\\.\\pipe\\ endpoint".into());
            }
        }
        "mtls_tcp" => {
            if manifest
                .transport
                .endpoint
                .parse::<std::net::SocketAddr>()
                .is_err()
                || [
                    manifest.transport.server_certificate_file.as_deref(),
                    manifest.transport.server_private_key_file.as_deref(),
                    manifest.transport.client_ca_file.as_deref(),
                ]
                .iter()
                .any(|path| path.is_none_or(|path| !Path::new(path).is_absolute()))
            {
                return Err("mTLS transport requires a socket address and absolute server certificate, private key, and client CA paths".into());
            }
        }
        _ => {
            return Err(
                "transport kind must be unix_socket, windows_named_pipe, or mtls_tcp".into(),
            )
        }
    }
    for path in [
        &manifest.policy.bootstrap_bundle,
        &manifest.policy.verifier_key_file,
        &manifest.keys.delegation_verifier_key_file,
        &manifest.keys.gateway_signing_key_file,
        &manifest.keys.approval_verifier_key_file,
        &manifest.keys.evidence_authorization_key_file,
    ] {
        if !Path::new(path).is_absolute() {
            return Err("policy and key paths must be absolute".to_string());
        }
    }
    if manifest.models.is_empty()
        || manifest.models.iter().any(|model| {
            model.provider.trim().is_empty()
                || model.model_id.trim().is_empty()
                || model.regions.is_empty()
                || !matches!(
                    model.retention.as_str(),
                    "none" | "local_only" | "provider_zero_retention"
                )
        })
    {
        return Err("at least one fully constrained model route is required".into());
    }
    let mut capability_ids = HashSet::new();
    for capability in &manifest.capabilities {
        if !capability_ids.insert(capability.id.as_str()) {
            return Err(format!("duplicate capability '{}'", capability.id));
        }
        let sensitive = matches!(
            capability.operation_class.as_str(),
            "destructive" | "credential" | "external_send" | "code_execution"
        );
        if capability.id.trim().is_empty()
            || capability.resource_type.trim().is_empty()
            || !matches!(
                capability.fail_mode.as_str(),
                "closed" | "cached" | "review"
            )
            || (sensitive && capability.fail_mode != "closed")
        {
            return Err(format!(
                "capability '{}' has an unsafe definition",
                capability.id
            ));
        }
    }
    if manifest
        .destinations
        .iter()
        .any(|destination| destination.tenant_id != manifest.agent.tenant_id)
    {
        return Err("cross-tenant destinations cannot be configured".into());
    }
    for approval in &manifest.approvals {
        if !capability_ids.contains(approval.capability_id.as_str())
            || approval.required_role.trim().is_empty()
            || approval.maximum_ttl_seconds == 0
            || approval.maximum_usage_count == 0
        {
            return Err("approval route is invalid or names an unknown capability".into());
        }
    }
    if manifest.retention.raw_evidence_seconds > 2_592_000
        || manifest.retention.telemetry_seconds == 0
        || manifest.retention.telemetry_max_bytes < 1_048_576
    {
        return Err("retention must be bounded and telemetry quota must be at least 1 MiB".into());
    }
    if manifest.adapters.iter().any(|adapter| {
        adapter.kind.trim().is_empty()
            || !matches!(adapter.fail_mode.as_str(), "closed" | "cached" | "review")
    }) {
        return Err("adapter configuration is invalid".into());
    }
    for broker in &manifest.http_brokers {
        let capability = manifest
            .capabilities
            .iter()
            .find(|capability| capability.id == broker.capability_id)
            .ok_or_else(|| "HTTP broker names an unknown capability".to_string())?;
        if !matches!(
            capability.operation_class.as_str(),
            "external_send" | "credential"
        ) || !broker.url_prefix.starts_with("https://")
            || !broker.url_prefix.ends_with('/')
            || broker.allowed_methods.is_empty()
            || broker.allowed_methods.iter().any(|method| {
                !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE")
            })
            || broker.credential_header.trim().is_empty()
            || !Path::new(&broker.credential_file).is_absolute()
            || !(1..=16 * 1024 * 1024).contains(&broker.maximum_response_bytes)
        {
            return Err("HTTP broker configuration is unsafe".into());
        }
    }
    for broker in &manifest.filesystem_brokers {
        let capability = manifest
            .capabilities
            .iter()
            .find(|capability| capability.id == broker.capability_id)
            .ok_or_else(|| "filesystem broker names an unknown capability".to_string())?;
        if capability.resource_type != "filesystem_path"
            || !Path::new(&broker.root).is_absolute()
            || broker.allowed_operations.is_empty()
            || broker
                .allowed_operations
                .iter()
                .any(|operation| !matches!(operation.as_str(), "read" | "write" | "remove"))
            || !(1..=64 * 1024 * 1024).contains(&broker.maximum_bytes)
        {
            return Err("filesystem broker configuration is unsafe".into());
        }
    }
    if manifest.protected_memory_keys.iter().any(|pattern| {
        pattern.trim().is_empty()
            || pattern.contains(char::is_whitespace)
            || pattern.matches('*').count() > 1
            || (pattern.contains('*') && !pattern.ends_with('*'))
    }) {
        return Err(
            "protected memory keys must be exact names or a single trailing '*' prefix pattern"
                .into(),
        );
    }
    for route in &manifest.declared_direct_routes {
        let capability = manifest
            .capabilities
            .iter()
            .find(|capability| capability.id == route.capability_id)
            .ok_or_else(|| "direct route names an unknown capability".to_string())?;
        if matches!(
            capability.operation_class.as_str(),
            "destructive" | "credential" | "external_send" | "code_execution"
        ) {
            return Err(format!(
                "sensitive capability '{}' has an unmediated route",
                capability.id
            ));
        }
    }
    Ok(())
}

fn explain_manifest(
    manifest: &AgentManifest,
    compiled: &CompiledManifest,
    requested: Option<&str>,
) -> Result<String, String> {
    let capabilities = manifest
        .capabilities
        .iter()
        .filter(|capability| requested.is_none_or(|id| capability.id == id))
        .map(|capability| {
            serde_json::json!({
                "capability_id": capability.id,
                "resource_type": capability.resource_type,
                "operation_class": capability.operation_class,
                "mediated": !manifest.declared_direct_routes.iter().any(|route| route.capability_id == capability.id),
                "required_receipt": capability.required_receipt,
                "fail_mode": capability.fail_mode,
                "explanation": "The sidecar evaluates identity and policy, then the gateway requires a signed single-use token."
            })
        })
        .collect::<Vec<_>>();
    if requested.is_some() && capabilities.is_empty() {
        return Err("requested capability is not declared".to_string());
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "manifest_digest": compiled.manifest_digest,
        "agent": compiled.agent,
        "capabilities": capabilities,
        "unenforced_capabilities": compiled.unenforced_capabilities,
    }))
    .map_err(|error| format!("failed to serialize manifest explanation: {error}"))
}

fn value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == name).then(|| pair[1].clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> AgentManifest {
        AgentManifest {
            schema_version: MANIFEST_VERSION.to_string(),
            agent: AgentIdentity {
                agent_id: "law-agent".into(),
                workload_identity: "spiffe://acme/agent/law-agent".into(),
                tenant_id: "tenant/acme".into(),
            },
            transport: TransportConfig {
                kind: "unix_socket".into(),
                endpoint: "/run/armorer/guard.sock".into(),
                server_certificate_file: None,
                server_private_key_file: None,
                client_ca_file: None,
            },
            policy: PolicyConfig {
                bootstrap_bundle: "/etc/guard/policy.json".into(),
                verifier_key_file: "/etc/guard/policy.key".into(),
            },
            keys: KeyConfig {
                delegation_verifier_key_file: "/etc/guard/delegation.key".into(),
                gateway_signing_key_file: "/etc/guard/gateway.key".into(),
                approval_verifier_key_file: "/etc/guard/approval.key".into(),
                evidence_authorization_key_file: "/etc/guard/evidence-authorization.key".into(),
            },
            models: vec![ModelRoute {
                provider: "openai".into(),
                model_id: "approved-model".into(),
                regions: vec!["us".into()],
                allowed_data_classes: vec!["legal_privileged".into()],
                retention: "provider_zero_retention".into(),
            }],
            capabilities: vec![CapabilitySpec {
                id: "case.delete".into(),
                resource_type: "legal_case".into(),
                operation_class: "destructive".into(),
                required_receipt: true,
                fail_mode: "closed".into(),
                max_dispatches_per_minute: Some(10),
                max_in_flight: None,
                max_arguments_bytes: None,
                failure_threshold_per_minute: None,
                circuit_break_seconds: None,
            }],
            destinations: vec![],
            approvals: vec![],
            retention: RetentionConfig {
                raw_evidence_seconds: 86_400,
                telemetry_seconds: 604_800,
                telemetry_max_bytes: 10_485_760,
            },
            adapters: vec![],
            http_brokers: vec![],
            filesystem_brokers: vec![],
            protected_memory_keys: vec!["identity.*".into(), "system.*".into()],
            declared_direct_routes: vec![],
        }
    }

    #[test]
    fn rejects_sensitive_unmediated_routes() {
        let mut value = manifest();
        value.declared_direct_routes.push(DirectRoute {
            capability_id: "case.delete".into(),
            reason: "legacy client".into(),
        });
        assert!(compile(&value).is_err());
    }

    #[test]
    fn compile_is_content_addressed() {
        let value = manifest();
        assert_eq!(
            compile(&value).unwrap().manifest_digest,
            compile(&value).unwrap().manifest_digest
        );
    }
}
