// Copyright 2026 John A Keeney - Entrouter
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Entrouter Universal
//!
//! Pipeline integrity guardian. What goes in, comes out identical.
//!
//! This crate provides Base64 encoding, SHA-256 fingerprinting, and integrity
//! verification primitives that can be composed into higher-level constructs:
//!
//! - [`Envelope`] -- wrap data in one of four modes (standard, URL-safe, compressed, TTL)
//! - [`Guardian`] -- track data through a multi-layer pipeline and detect where mutations occur
//! - [`Chain`] -- build a cryptographic audit trail where each link references the previous
//! - [`UniversalStruct`] -- wrap individual struct fields so you know *which* field was tampered with
//!
//! # Quick start
//!
//! ```rust
//! use entrouter_universal::{encode_str, decode_str, fingerprint_str, verify};
//!
//! let encoded = encode_str("hello world");
//! let fp = fingerprint_str("hello world");
//! let result = verify(&encoded, &fp).unwrap();
//! assert!(result.intact);
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod chain;
pub mod envelope;
pub mod guardian;
pub mod signed_envelope;
pub mod universal_struct;
pub mod verify;

#[cfg(feature = "compression")]
pub mod compress;

pub use chain::Chain;
pub use chain::ChainDiff;
pub use envelope::Envelope;
pub use guardian::Guardian;
pub use signed_envelope::SignedEnvelope;
pub use universal_struct::UniversalStruct;
pub use verify::VerifyResult;

// ── Errors ────────────────────────────────────────────────

/// Errors returned by Entrouter Universal operations.
#[derive(Debug, Clone, PartialEq, Error)]
#[non_exhaustive]
pub enum UniversalError {
    #[error("Integrity violation: data was mutated in transit. Expected {expected}, got {actual}")]
    IntegrityViolation { expected: String, actual: String },

    #[error("Decode error: {0}")]
    DecodeError(String),

    #[error("Envelope malformed: {0}")]
    MalformedEnvelope(String),

    #[error("Expired: envelope expired at {expired_at}, current time {now}")]
    Expired { expired_at: u64, now: u64 },

    #[error("Compress error: {0}")]
    CompressError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Chain merge conflict: chains diverge at link {diverges_at}")]
    ChainMergeConflict { diverges_at: usize },
}

// ── Core primitives ───────────────────────────────────────

/// Base64-encode raw bytes.
///
/// ```
/// let b64 = entrouter_universal::encode(b"hello");
/// assert_eq!(b64, "aGVsbG8=");
/// ```
#[must_use]
pub fn encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode a Base64 string back to raw bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, UniversalError> {
    STANDARD
        .decode(input)
        .map_err(|e| UniversalError::DecodeError(e.to_string()))
}

/// Base64-encode a UTF-8 string.
///
/// ```
/// let b64 = entrouter_universal::encode_str("hello");
/// assert_eq!(entrouter_universal::decode_str(&b64).unwrap(), "hello");
/// ```
#[must_use]
pub fn encode_str(input: &str) -> String {
    encode(input.as_bytes())
}

/// Decode a Base64 string back to a UTF-8 [`String`].
pub fn decode_str(input: &str) -> Result<String, UniversalError> {
    let bytes = decode(input)?;
    String::from_utf8(bytes).map_err(|e| UniversalError::DecodeError(e.to_string()))
}

/// Compute a SHA-256 fingerprint of raw bytes, returned as a hex string.
///
/// ```
/// let fp = entrouter_universal::fingerprint(b"hello");
/// assert_eq!(fp.len(), 64); // 256-bit hex
/// ```
#[must_use]
pub fn fingerprint(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

/// Compute a SHA-256 fingerprint of a UTF-8 string.
#[must_use]
pub fn fingerprint_str(input: &str) -> String {
    fingerprint(input.as_bytes())
}

/// Decode `encoded` and verify its fingerprint matches `original_fingerprint`.
///
/// Returns [`VerifyResult`] on success, or [`UniversalError::IntegrityViolation`]
/// if the data was mutated.
pub fn verify(encoded: &str, original_fingerprint: &str) -> Result<VerifyResult, UniversalError> {
    let decoded = decode(encoded)?;
    let actual_fingerprint = fingerprint(&decoded);
    if actual_fingerprint == original_fingerprint {
        Ok(VerifyResult {
            intact: true,
            decoded,
            fingerprint: actual_fingerprint,
        })
    } else {
        Err(UniversalError::IntegrityViolation {
            expected: original_fingerprint.to_string(),
            actual: actual_fingerprint,
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    // ── Core ─────────────────────────────────────────────

    #[test]
    fn round_trip_special_chars() {
        let original = r#"hello "world" it's \fine\ with 日本語 and 🔥"#;
        assert_eq!(original, decode_str(&encode_str(original)).unwrap());
    }

    // ── Envelope modes ────────────────────────────────────

    #[test]
    fn envelope_standard() {
        let data = r#"{"token":"abc\"def","user":"john's"}"#;
        let env = Envelope::wrap(data);
        assert_eq!(data, env.unwrap_verified().unwrap());
    }

    #[test]
    fn envelope_url_safe() {
        let data = "race_token: abc\"123\"\nspecial chars & stuff";
        let env = Envelope::wrap_url_safe(data);
        // URL safe chars only
        assert!(env
            .d
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
        assert_eq!(data, env.unwrap_verified().unwrap());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn envelope_compressed() {
        // Repeated data compresses well
        let data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".repeat(100);
        let env = Envelope::wrap_compressed(&data).unwrap();
        // Compressed + Base64 should be smaller than raw
        assert!(env.d.len() < data.len());
        assert_eq!(data, env.unwrap_verified().unwrap());
    }

    #[test]
    fn envelope_ttl_valid() {
        let env = Envelope::wrap_with_ttl("fresh data", 60);
        assert!(!env.is_expired());
        assert_eq!("fresh data", env.unwrap_verified().unwrap());
    }

    #[test]
    fn envelope_ttl_expired() {
        let env = Envelope::wrap_with_ttl("stale data", 0);
        sleep(Duration::from_millis(10));
        assert!(env.is_expired());
        assert!(env.unwrap_verified().is_err());
    }

    #[test]
    fn envelope_detects_mutation() {
        let env = Envelope::wrap("original");
        let mut json = env.to_json().unwrap();
        // Flip a character in the encoded data
        let idx = json.find('"').unwrap() + 5;
        json.replace_range(idx..idx + 1, "X");
        let tampered = Envelope::from_json(&json);
        let result = tampered.and_then(|e| e.unwrap_verified());
        assert!(result.is_err());
    }

    // ── Chain ─────────────────────────────────────────────

    #[test]
    fn chain_builds_and_verifies() {
        let mut chain = Chain::new("genesis: race started");
        chain.append("link 2: user_a joined");
        chain.append("link 3: user_b joined");
        chain.append("link 4: winner = user_a");

        let result = chain.verify();
        assert!(result.valid);
        assert_eq!(result.total_links, 4);
    }

    #[test]
    fn chain_detects_tampering() {
        let mut chain = Chain::new("genesis");
        chain.append("link 2");
        chain.append("link 3");

        // Tamper with link 2's data
        let mut tampered = chain.clone();
        tampered.links[1].d = encode_str("TAMPERED");

        let result = tampered.verify();
        assert!(!result.valid);
        assert_eq!(result.broken_at, Some(2));
    }

    #[test]
    fn chain_serialises_round_trip() {
        let mut chain = Chain::new("start");
        chain.append("middle");
        chain.append("end");

        let json = chain.to_json().unwrap();
        let restored = Chain::from_json(&json).unwrap();
        assert!(restored.verify().valid);
    }

    // ── UniversalStruct ───────────────────────────────────

    #[test]
    fn struct_wraps_all_fields() {
        let wrapped = UniversalStruct::wrap_fields(&[
            ("token", "000001739850123456-abc\"def"),
            ("user_id", "john's account"),
            ("amount", "99.99"),
        ]);

        let result = wrapped.verify_all();
        assert!(result.all_intact);
        assert_eq!(wrapped.get("token").unwrap(), "000001739850123456-abc\"def");
        assert_eq!(wrapped.get("user_id").unwrap(), "john's account");
        assert_eq!(wrapped.get("amount").unwrap(), "99.99");
    }

    #[test]
    fn struct_detects_field_mutation() {
        let mut wrapped = UniversalStruct::wrap_fields(&[
            ("token", "abc123"),
            ("user_id", "john"),
            ("amount", "99.99"),
        ]);

        // Mutate just the amount field
        wrapped.fields[2].d = encode_str("999999.99");

        let result = wrapped.verify_all();
        assert!(!result.all_intact);
        assert!(result.violations.contains(&"amount".to_string()));
        // Other fields still intact
        assert!(result.fields[0].intact);
        assert!(result.fields[1].intact);
        assert!(!result.fields[2].intact);
    }

    #[test]
    fn struct_to_map() {
        let wrapped = UniversalStruct::wrap_fields(&[("a", "hello"), ("b", "world")]);
        let map = wrapped.to_map().unwrap();
        assert_eq!(map["a"], "hello");
        assert_eq!(map["b"], "world");
    }

    #[test]
    fn struct_serialises_round_trip() {
        let wrapped =
            UniversalStruct::wrap_fields(&[("token", r#"abc"def\ghi"#), ("user", "john")]);
        let json = wrapped.to_json().unwrap();
        let restored = UniversalStruct::from_json(&json).unwrap();
        restored.assert_intact();
        assert_eq!(restored.get("token").unwrap(), r#"abc"def\ghi"#);
    }

    // ── Guardian ──────────────────────────────────────────

    #[test]
    fn guardian_clean_pipeline() {
        let mut g = Guardian::new("clean data 🔥");
        let encoded = g.encoded().to_string();
        g.checkpoint("http", &encoded);
        g.checkpoint("redis", &encoded);
        g.checkpoint("postgres", &encoded);
        g.assert_intact();
    }

    #[test]
    fn guardian_finds_violation() {
        let mut g = Guardian::new("original");
        let clean = g.encoded().to_string();
        g.checkpoint("http", &clean);
        g.checkpoint("redis", &encode_str("mangled"));
        assert_eq!(g.first_violation().unwrap().layer, "redis");
    }
}
