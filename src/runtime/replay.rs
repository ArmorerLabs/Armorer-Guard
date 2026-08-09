use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

use super::contracts::AuthorityRequestV2;
use super::crypto;
use crate::policy::PolicyEffect;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRecord {
    pub schema_version: String,
    pub replay_id: String,
    pub authority_request: AuthorityRequestV2,
    pub approval_roles: Vec<String>,
    pub original_effect: PolicyEffect,
    pub original_reason_codes: Vec<String>,
    pub original_policy_revision: u64,
    pub original_policy_digest: String,
    pub recorded_at: u64,
}

#[derive(Deserialize, Serialize)]
struct EncryptedReplayRecord {
    schema_version: String,
    replay_id: String,
    trace_id: String,
    tenant_id: String,
    nonce: String,
    ciphertext: String,
    expires_at: u64,
}

pub struct ReplayStore {
    path: PathBuf,
    key: [u8; 32],
    retention_seconds: u64,
    records_since_sync: u32,
}

impl ReplayStore {
    pub fn new(path: PathBuf, key: Vec<u8>, retention_seconds: u64) -> Result<Self, String> {
        if key.len() < 32 || retention_seconds == 0 {
            return Err("replay storage requires a 32-byte key and bounded retention".to_string());
        }
        let mut normalized = [0u8; 32];
        normalized.copy_from_slice(&key[..32]);
        Ok(Self {
            path,
            key: normalized,
            retention_seconds,
            records_since_sync: 0,
        })
    }

    pub fn append(&mut self, record: &ReplayRecord) -> Result<(), String> {
        let plaintext = crypto::canonical_bytes(record)?;
        let nonce_seed = serde_json::json!({
            "replay_id": record.replay_id,
            "recorded_at": record.recorded_at,
            "nonce_id": crypto::opaque_id("replay", &self.key),
        });
        let nonce_bytes = crypto::hmac_sha256(&self.key, &crypto::canonical_bytes(&nonce_seed)?);
        let aad = format!(
            "{}|{}|{}",
            record.replay_id,
            record.authority_request.context.trace_id,
            record.authority_request.subject.tenant_id
        );
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(
                Nonce::from_slice(&nonce_bytes[..12]),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "failed to encrypt replay record".to_string())?;
        let encrypted = EncryptedReplayRecord {
            schema_version: "armorer-guard-encrypted-replay/v1".to_string(),
            replay_id: record.replay_id.clone(),
            trace_id: record.authority_request.context.trace_id.clone(),
            tenant_id: record.authority_request.subject.tenant_id.clone(),
            nonce: hex(&nonce_bytes[..12]),
            ciphertext: hex(&ciphertext),
            expires_at: record.recorded_at.saturating_add(self.retention_seconds),
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create replay directory: {error}"))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("failed to open replay store: {error}"))?;
        serde_json::to_writer(&mut file, &encrypted)
            .map_err(|error| format!("failed to encode replay record: {error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("failed to append replay record: {error}"))?;
        self.records_since_sync = self.records_since_sync.saturating_add(1);
        if self.records_since_sync >= 32 {
            file.sync_data()
                .map_err(|error| format!("failed to flush replay store: {error}"))?;
            self.records_since_sync = 0;
        }
        Ok(())
    }

    pub fn query(
        &self,
        trace_id: &str,
        observed_at: u64,
        limit: usize,
    ) -> Result<Vec<ReplayRecord>, String> {
        let Ok(contents) = fs::read_to_string(&self.path) else {
            return Ok(Vec::new());
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut records = Vec::new();
        for line in contents.lines().rev() {
            let encrypted: EncryptedReplayRecord = serde_json::from_str(line)
                .map_err(|error| format!("replay store is corrupt: {error}"))?;
            if encrypted.trace_id != trace_id || encrypted.expires_at < observed_at {
                continue;
            }
            let nonce = unhex(&encrypted.nonce)?;
            let ciphertext = unhex(&encrypted.ciphertext)?;
            if nonce.len() != 12 {
                return Err("replay nonce is invalid".to_string());
            }
            let aad = format!(
                "{}|{}|{}",
                encrypted.replay_id, encrypted.trace_id, encrypted.tenant_id
            );
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| "replay record authentication failed".to_string())?;
            records.push(
                serde_json::from_slice(&plaintext)
                    .map_err(|error| format!("replay record is invalid: {error}"))?,
            );
            if records.len() >= limit {
                break;
            }
        }
        records.reverse();
        Ok(records)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("replay encoding is invalid".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let text =
                std::str::from_utf8(chunk).map_err(|_| "replay encoding is invalid".to_string())?;
            u8::from_str_radix(text, 16).map_err(|_| "replay encoding is invalid".to_string())
        })
        .collect()
}
