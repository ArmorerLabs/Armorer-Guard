use std::fs;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

use super::atomic_store;
use super::contracts::ContentEvaluationRequest;
use super::crypto;

#[derive(Deserialize, Serialize)]
struct EvidenceRecord {
    schema_version: String,
    content_ref: String,
    trace_id: String,
    tenant_id: String,
    stage: String,
    nonce: String,
    ciphertext: String,
    expires_at: u64,
}

pub struct EvidenceVault {
    path: PathBuf,
    key: [u8; 32],
    maximum_retention_seconds: u64,
}

impl EvidenceVault {
    pub fn new(
        path: PathBuf,
        key: Vec<u8>,
        maximum_retention_seconds: u64,
    ) -> Result<Self, String> {
        if key.len() < 32 {
            return Err("evidence encryption key must contain at least 32 bytes".to_string());
        }
        let mut normalized = [0u8; 32];
        normalized.copy_from_slice(&key[..32]);
        Ok(Self {
            path,
            key: normalized,
            maximum_retention_seconds,
        })
    }

    pub fn retain(
        &self,
        request: &ContentEvaluationRequest,
        stage: &str,
        observed_at: u64,
    ) -> Result<(), String> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        for segment in &request.segments {
            if matches!(segment.retention.as_str(), "none" | "ephemeral") {
                continue;
            }
            let nonce_seed = serde_json::json!({
                "content_ref": segment.content_ref,
                "trace_id": request.trace_id,
                "stage": stage,
                "observed_at": observed_at,
                "nonce_id": crypto::opaque_id("evidence", &self.key),
            });
            let nonce_bytes =
                crypto::hmac_sha256(&self.key, &crypto::canonical_bytes(&nonce_seed)?);
            let nonce = Nonce::from_slice(&nonce_bytes[..12]);
            let aad = format!(
                "{}|{}|{}|{}",
                segment.content_ref, request.trace_id, request.subject.tenant_id, stage
            );
            let ciphertext = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: segment.text.as_bytes(),
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| "failed to encrypt local evidence".to_string())?;
            let record = EvidenceRecord {
                schema_version: "armorer-guard-encrypted-evidence/v1".to_string(),
                content_ref: segment.content_ref.clone(),
                trace_id: request.trace_id.clone(),
                tenant_id: request.subject.tenant_id.clone(),
                stage: stage.to_string(),
                nonce: hex(&nonce_bytes[..12]),
                ciphertext: hex(&ciphertext),
                expires_at: observed_at.saturating_add(self.maximum_retention_seconds),
            };
            atomic_store::append_json(&self.path, &record)?;
        }
        Ok(())
    }

    pub fn retrieve(
        &self,
        content_ref: &str,
        trace_id: &str,
        tenant_id: &str,
        observed_at: u64,
    ) -> Result<(String, String), String> {
        let contents = fs::read_to_string(&self.path)
            .map_err(|error| format!("failed to read encrypted evidence: {error}"))?;
        let record = contents
            .lines()
            .rev()
            .filter_map(|line| serde_json::from_str::<EvidenceRecord>(line).ok())
            .find(|record| {
                record.content_ref == content_ref
                    && record.trace_id == trace_id
                    && record.tenant_id == tenant_id
                    && record.expires_at >= observed_at
            })
            .ok_or_else(|| "authorized evidence was not found or has expired".to_string())?;
        let nonce_bytes = unhex(&record.nonce)?;
        if nonce_bytes.len() != 12 {
            return Err("encrypted evidence nonce is invalid".to_string());
        }
        let ciphertext = unhex(&record.ciphertext)?;
        let aad = format!(
            "{}|{}|{}|{}",
            record.content_ref, record.trace_id, record.tenant_id, record.stage
        );
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "encrypted evidence authentication failed".to_string())?;
        String::from_utf8(plaintext)
            .map(|text| (text, record.stage))
            .map_err(|_| "encrypted evidence is not UTF-8".to_string())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("encrypted evidence encoding is invalid".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk)
                .map_err(|_| "encrypted evidence encoding is invalid".to_string())?;
            u8::from_str_radix(text, 16)
                .map_err(|_| "encrypted evidence encoding is invalid".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::contracts::{
        ContentEvaluationRequest, ContentSegment, InstructionAuthority, RuntimeSubject, TrustClass,
        CONTENT_REQUEST_VERSION,
    };

    #[test]
    fn vault_never_writes_plaintext() {
        let root = std::env::temp_dir()
            .join(crypto::opaque_id("evidence-test", &[9; 32]).replace('/', "-"));
        let path = root.join("evidence.jsonl");
        let vault = EvidenceVault::new(path.clone(), vec![9; 32], 60).unwrap();
        let secret = "privileged evidence text";
        vault
            .retain(
                &ContentEvaluationRequest {
                    schema_version: CONTENT_REQUEST_VERSION.into(),
                    request_id: "request/1".into(),
                    trace_id: "trace/1".into(),
                    session_id: "session/1".into(),
                    subject: RuntimeSubject {
                        agent_id: "agent".into(),
                        identity_id: "identity".into(),
                        tenant_id: "tenant".into(),
                    },
                    purpose: Some("test".into()),
                    allowed_context_origins: vec![],
                    model_route: None,
                    segments: vec![ContentSegment {
                        content_ref: "content/sha256:a".into(),
                        origin: "upload".into(),
                        principal_id: "user".into(),
                        tenant_id: "tenant".into(),
                        trust: TrustClass::Untrusted,
                        data_classes: vec![],
                        instruction_authority: InstructionAuthority::None,
                        retention: "local_only".into(),
                        influenced_by: vec![],
                        text: secret.into(),
                    }],
                    destination: None,
                    memory_target: None,
                },
                "input",
                10,
            )
            .unwrap();
        let stored = std::fs::read_to_string(path).unwrap();
        assert!(!stored.contains(secret));
        assert!(!stored.contains("chacha"));
    }
}
