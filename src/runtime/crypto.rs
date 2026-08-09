use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

static NONCE: AtomicU64 = AtomicU64::new(1);

pub(super) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value)
        .map_err(|error| format!("failed to encode canonical value: {error}"))?;
    serde_json::to_vec(&canonical_value(value))
        .map_err(|error| format!("failed to serialize canonical value: {error}"))
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut canonical = Map::new();
            for (key, value) in entries {
                canonical.insert(key, canonical_value(value));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_value).collect()),
        other => other,
    }
}

pub(super) fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        hex(&Sha256::digest(canonical_bytes(value)?))
    ))
}

pub(super) fn addressed_id<T: Serialize>(kind: &str, value: &T) -> String {
    let encoded = canonical_bytes(value).unwrap_or_default();
    format!("{kind}/sha256:{}", hex(&Sha256::digest(encoded)))
}

pub(super) fn sign<T: Serialize>(key: &[u8], value: &T) -> Result<String, String> {
    Ok(format!(
        "hmac-sha256:{}",
        hex(&hmac_sha256(key, &canonical_bytes(value)?))
    ))
}

pub(super) fn verify<T: Serialize>(key: &[u8], value: &T, signature: &str) -> bool {
    sign(key, value)
        .map(|expected| constant_time_eq(expected.as_bytes(), signature.as_bytes()))
        .unwrap_or(false)
}

pub(super) fn opaque_id(kind: &str, key: &[u8]) -> String {
    #[derive(Serialize)]
    struct Seed {
        nanos: u128,
        pid: u32,
        counter: u64,
    }
    let seed = Seed {
        nanos: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        pid: std::process::id(),
        counter: NONCE.fetch_add(1, Ordering::Relaxed),
    };
    let signature = sign(key, &seed).unwrap_or_else(|_| "hmac-sha256:invalid".to_string());
    format!("{kind}/{}", signature.trim_start_matches("hmac-sha256:"))
}

pub(super) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_objects_have_stable_digests() {
        let left = serde_json::json!({"b": 2, "a": {"d": 4, "c": 3}});
        let right = serde_json::json!({"a": {"c": 3, "d": 4}, "b": 2});
        assert_eq!(digest(&left).unwrap(), digest(&right).unwrap());
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn signatures_reject_mutation() {
        let signature = sign(&[7; 32], &serde_json::json!({"case": 1})).unwrap();
        assert!(verify(
            &[7; 32],
            &serde_json::json!({"case": 1}),
            &signature
        ));
        assert!(!verify(
            &[7; 32],
            &serde_json::json!({"case": 2}),
            &signature
        ));
    }

    #[test]
    fn canonical_contract_vectors_match() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../fixtures/canonical-contract-vectors.json"
        ))
        .unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let value = &vector["value"];
            assert_eq!(
                String::from_utf8(canonical_bytes(value).unwrap()).unwrap(),
                vector["canonical_json"].as_str().unwrap()
            );
            assert_eq!(digest(value).unwrap(), vector["digest"].as_str().unwrap());
            assert_eq!(
                sign(&[7; 32], value).unwrap(),
                vector["signature"].as_str().unwrap()
            );
        }
    }
}
