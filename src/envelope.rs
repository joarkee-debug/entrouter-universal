// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal - Envelope v2
//
//  Four wrap modes:
//  1. wrap()             - standard Base64
//  2. wrap_url_safe()    - URL-safe Base64 (- and _ instead of + and /)
//  3. wrap_compressed()  - gzip then Base64 (smaller wire size)
//  4. wrap_with_ttl()    - standard Base64 + expiry timestamp
//
//  All modes carry a SHA-256 fingerprint.
//  All modes unwrap via unwrap_verified().
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{fingerprint_str, UniversalError};

#[cfg(feature = "compression")]
use crate::compress::{compress, decompress};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EnvelopeMode {
    Standard,
    UrlSafe,
    Compressed,
    Ttl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Encoded data - opaque to every layer
    pub d: String,
    /// SHA-256 fingerprint of the ORIGINAL raw input (before compression)
    pub f: String,
    /// Encoding mode
    pub m: EnvelopeMode,
    /// Optional expiry as Unix timestamp (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<u64>,
    /// Version
    pub v: u8,
}

impl Envelope {
    // ── Constructors ──────────────────────────────────────

    /// Standard Base64 wrap.
    pub fn wrap(input: &str) -> Self {
        Self {
            d: STANDARD.encode(input.as_bytes()),
            f: fingerprint_str(input),
            m: EnvelopeMode::Standard,
            e: None,
            v: 2,
        }
    }

    /// URL-safe Base64 wrap.
    /// Use when passing through URLs, query params, or HTTP headers.
    /// Uses `-` and `_` instead of `+` and `/`. No padding.
    pub fn wrap_url_safe(input: &str) -> Self {
        Self {
            d: URL_SAFE_NO_PAD.encode(input.as_bytes()),
            f: fingerprint_str(input),
            m: EnvelopeMode::UrlSafe,
            e: None,
            v: 2,
        }
    }

    /// Compressed wrap - gzip then Base64.
    /// Use for large payloads. Transparent to consumer - unwrap_verified()
    /// returns the original uncompressed string.
    #[cfg(feature = "compression")]
    pub fn wrap_compressed(input: &str) -> Result<Self, UniversalError> {
        let compressed = compress(input.as_bytes())?;
        Ok(Self {
            d: STANDARD.encode(&compressed),
            f: fingerprint_str(input),
            m: EnvelopeMode::Compressed,
            e: None,
            v: 2,
        })
    }

    /// TTL wrap - standard Base64 with an expiry time.
    /// unwrap_verified() returns Err if the envelope has expired.
    pub fn wrap_with_ttl(input: &str, ttl_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            d: STANDARD.encode(input.as_bytes()),
            f: fingerprint_str(input),
            m: EnvelopeMode::Ttl,
            e: Some(now + ttl_secs),
            v: 2,
        }
    }

    // ── Unwrap ────────────────────────────────────────────

    /// Decode and verify integrity at the exit point.
    /// Works for all modes. Returns Err on:
    /// - Integrity violation (data mutated in transit)
    /// - Expired TTL
    /// - Decode/decompress failure
    pub fn unwrap_verified(&self) -> Result<String, UniversalError> {
        // TTL check first
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
            EnvelopeMode::Standard | EnvelopeMode::Ttl => {
                STANDARD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?
            }
            EnvelopeMode::UrlSafe => {
                URL_SAFE_NO_PAD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?
            }
            #[cfg(feature = "compression")]
            EnvelopeMode::Compressed => {
                let compressed = STANDARD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?;
                decompress(&compressed)?
            }
            #[cfg(not(feature = "compression"))]
            EnvelopeMode::Compressed => {
                return Err(UniversalError::DecodeError(
                    "compression feature not enabled".to_string()
                ))
            }
        };

        let decoded = String::from_utf8(bytes)
            .map_err(|e| UniversalError::DecodeError(e.to_string()))?;

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

    /// Decode without verification - use when you trust the source.
    pub fn unwrap_raw(&self) -> Result<String, UniversalError> {
        let bytes = match self.m {
            EnvelopeMode::Standard | EnvelopeMode::Ttl => {
                STANDARD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?
            }
            EnvelopeMode::UrlSafe => {
                URL_SAFE_NO_PAD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?
            }
            #[cfg(feature = "compression")]
            EnvelopeMode::Compressed => {
                let compressed = STANDARD.decode(&self.d)
                    .map_err(|e| UniversalError::DecodeError(e.to_string()))?;
                decompress(&compressed)?
            }
            #[cfg(not(feature = "compression"))]
            EnvelopeMode::Compressed => {
                return Err(UniversalError::DecodeError(
                    "compression feature not enabled".to_string()
                ))
            }
        };
        String::from_utf8(bytes)
            .map_err(|e| UniversalError::DecodeError(e.to_string()))
    }

    /// Check if expired (TTL mode only)
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.e {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            return now >= expiry;
        }
        false
    }

    /// Seconds remaining until expiry. None if no TTL set.
    pub fn ttl_remaining(&self) -> Option<u64> {
        let expiry = self.e?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(expiry.saturating_sub(now))
    }

    pub fn is_intact(&self) -> bool {
        self.unwrap_verified().is_ok()
    }

    pub fn fingerprint(&self) -> &str {
        &self.f
    }

    pub fn mode(&self) -> EnvelopeMode {
        self.m
    }

    pub fn to_json(&self) -> Result<String, UniversalError> {
        serde_json::to_string(self)
            .map_err(|e| UniversalError::MalformedEnvelope(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self, UniversalError> {
        serde_json::from_str(s)
            .map_err(|e| UniversalError::MalformedEnvelope(e.to_string()))
    }
}
