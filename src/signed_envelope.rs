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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal - HMAC-Signed Envelope v3
//
//  Like Envelope, but with HMAC-SHA256 authentication.
//  Proves both integrity (SHA-256 fingerprint) AND origin
//  (only someone with the key could produce the signature).
//
//  Modes: Standard, UrlSafe, Compressed, Ttl
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::{fingerprint_str, UniversalError};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "compression")]
use crate::compress::{compress, decompress};

type HmacSha256 = Hmac<Sha256>;

/// The encoding mode used to create a [`SignedEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SignedEnvelopeMode {
    Standard,
    UrlSafe,
    Compressed,
    Ttl,
}

/// A sealed, HMAC-authenticated envelope.
///
/// Carries data, its SHA-256 fingerprint, and an HMAC-SHA256 signature
/// over the fingerprint. Unwrapping requires the same key used to sign.
///
/// # Example
///
/// ```
/// use entrouter_universal::SignedEnvelope;
///
/// let env = SignedEnvelope::wrap("secret", "my-key");
/// assert_eq!(env.unwrap_verified("my-key").unwrap(), "secret");
/// assert!(env.unwrap_verified("wrong-key").is_err());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// Encoded data
    pub d: String,
    /// SHA-256 fingerprint of the original raw input
    pub f: String,
    /// HMAC-SHA256 signature (hex) over the fingerprint
    pub sig: String,
    /// Encoding mode
    pub m: SignedEnvelopeMode,
    /// Optional expiry as Unix timestamp (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<u64>,
    /// Version
    pub v: u8,
}

fn hmac_sign(fingerprint: &str, key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(fingerprint.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_verify(fingerprint: &str, key: &str, sig: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(fingerprint.as_bytes());
    let expected = hex::decode(sig).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}

impl SignedEnvelope {
    // ── Constructors ──────────────────────────────────────

    /// Standard Base64 wrap with HMAC signature.
    #[must_use]
    pub fn wrap(input: &str, key: &str) -> Self {
        let fp = fingerprint_str(input);
        Self {
            d: STANDARD.encode(input.as_bytes()),
            sig: hmac_sign(&fp, key),
            f: fp,
            m: SignedEnvelopeMode::Standard,
            e: None,
            v: 3,
        }
    }

    /// URL-safe Base64 wrap with HMAC signature.
    #[must_use]
    pub fn wrap_url_safe(input: &str, key: &str) -> Self {
        let fp = fingerprint_str(input);
        Self {
            d: URL_SAFE_NO_PAD.encode(input.as_bytes()),
            sig: hmac_sign(&fp, key),
            f: fp,
            m: SignedEnvelopeMode::UrlSafe,
            e: None,
            v: 3,
        }
    }

    /// Compressed wrap with HMAC signature.
    #[cfg(feature = "compression")]
    pub fn wrap_compressed(input: &str, key: &str) -> Result<Self, UniversalError> {
        let compressed = compress(input.as_bytes())?;
        let fp = fingerprint_str(input);
        Ok(Self {
            d: STANDARD.encode(&compressed),
            sig: hmac_sign(&fp, key),
            f: fp,
            m: SignedEnvelopeMode::Compressed,
            e: None,
            v: 3,
        })
    }

    /// TTL wrap with HMAC signature.
    #[must_use]
    pub fn wrap_with_ttl(input: &str, key: &str, ttl_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let fp = fingerprint_str(input);
        Self {
            d: STANDARD.encode(input.as_bytes()),
            sig: hmac_sign(&fp, key),
            f: fp,
            m: SignedEnvelopeMode::Ttl,
            e: Some(now + ttl_secs),
            v: 3,
        }
    }

    // ── Unwrap ────────────────────────────────────────────

    /// Verify HMAC signature, then decode and verify integrity.
    pub fn unwrap_verified(&self, key: &str) -> Result<String, UniversalError> {
        // HMAC check first -- reject before decoding
        if !hmac_verify(&self.f, key, &self.sig) {
            return Err(UniversalError::MalformedEnvelope(
                "HMAC signature invalid -- wrong key or tampered envelope".into(),
            ));
        }

        // TTL check
        if let Some(expiry) = self.e {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= expiry {
                return Err(UniversalError::Expired {
                    expired_at: expiry,
                    now,
                });
            }
        }

        // Decode
        let bytes = match self.m {
            SignedEnvelopeMode::Standard | SignedEnvelopeMode::Ttl => STANDARD
                .decode(&self.d)
                .map_err(|e| UniversalError::DecodeError(e.to_string()))?,
            SignedEnvelopeMode::UrlSafe => URL_SAFE_NO_PAD
                .decode(&self.d)
                .map_err(|e| UniversalError::DecodeError(e.to_string()))?,
            #[cfg(feature = "compression")]
            SignedEnvelopeMode::Compressed => {
                let compressed = STANDARD
                    .decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?;
                decompress(&compressed)?
            }
            #[cfg(not(feature = "compression"))]
            SignedEnvelopeMode::Compressed => {
                return Err(UniversalError::DecodeError(
                    "compression feature not enabled".to_string(),
                ))
            }
        };

        let decoded =
            String::from_utf8(bytes).map_err(|e| UniversalError::DecodeError(e.to_string()))?;

        // Verify fingerprint
        let actual_fp = fingerprint_str(&decoded);
        if actual_fp != self.f {
            return Err(UniversalError::IntegrityViolation {
                expected: self.f.clone(),
                actual: actual_fp,
            });
        }

        Ok(decoded)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, UniversalError> {
        serde_json::to_string(self).map_err(|e| UniversalError::SerializationError(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(s: &str) -> Result<Self, UniversalError> {
        serde_json::from_str(s).map_err(|e| UniversalError::SerializationError(e.to_string()))
    }
}
