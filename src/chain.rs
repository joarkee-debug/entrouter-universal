// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal - Chain Verification
//
//  Each link in the chain references the previous link's
//  fingerprint. Unbreakable sequence. Cryptographic audit trail.
//
//  Use case: race results, financial transactions, anything
//  where ORDER and INTEGRITY both matter.
//
//  If someone tampers with link 3 of a 10-link chain,
//  links 4-10 all break simultaneously. You know exactly
//  where the chain was cut.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{encode_str, fingerprint_str, UniversalError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    /// Sequence number (1-based)
    pub seq: u64,
    /// Base64 encoded data
    pub d: String,
    /// Fingerprint of THIS link's raw data
    pub f: String,
    /// Fingerprint of the PREVIOUS link (None for genesis)
    pub prev: Option<String>,
    /// Unix timestamp when this link was created
    pub ts: u64,
}

impl ChainLink {
    /// Verify this link's data integrity
    pub fn verify_data(&self) -> Result<String, UniversalError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(&self.d)
            .map_err(|e| UniversalError::DecodeError(e.to_string()))?;
        let decoded = String::from_utf8(bytes)
            .map_err(|e| UniversalError::DecodeError(e.to_string()))?;
        let data_fp = fingerprint_str(&decoded);
        // Non-genesis links have a chained fingerprint
        let actual_fp = match &self.prev {
            Some(prev) => fingerprint_str(&format!("{}{}", data_fp, prev)),
            None => data_fp,
        };
        if actual_fp != self.f {
            return Err(UniversalError::IntegrityViolation {
                expected: self.f.clone(),
                actual: actual_fp,
            });
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone)]
pub struct ChainVerifyResult {
    pub valid:          bool,
    pub total_links:    usize,
    pub broken_at:      Option<usize>,
    pub broken_reason:  Option<String>,
}

/// A cryptographic chain of data.
/// Each link proves it came after the previous one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub links: Vec<ChainLink>,
}

impl Chain {
    /// Start a new chain with a genesis link
    pub fn new(data: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let link = ChainLink {
            seq:  1,
            d:    encode_str(data),
            f:    fingerprint_str(data),
            prev: None,
            ts,
        };

        Self { links: vec![link] }
    }

    /// Append a new link referencing the previous link's fingerprint
    pub fn append(&mut self, data: &str) -> &ChainLink {
        let prev_fp = self.links.last().map(|l| l.f.clone());
        let seq = self.links.len() as u64 + 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Chain fingerprint includes previous link's fingerprint
        // so you can't reorder or insert links without breaking everything after
        let combined = format!("{}{}", fingerprint_str(data), prev_fp.as_deref().unwrap_or(""));
        let chained_fp = fingerprint_str(&combined);

        self.links.push(ChainLink {
            seq,
            d:    encode_str(data),
            f:    chained_fp,
            prev: prev_fp,
            ts,
        });

        self.links.last().unwrap()
    }

    /// Verify the entire chain - every link's data AND every link's
    /// reference to the previous link's fingerprint
    pub fn verify(&self) -> ChainVerifyResult {
        if self.links.is_empty() {
            return ChainVerifyResult {
                valid: true,
                total_links: 0,
                broken_at: None,
                broken_reason: None,
            };
        }

        for (i, link) in self.links.iter().enumerate() {
            // Verify data integrity
            if let Err(e) = link.verify_data() {
                return ChainVerifyResult {
                    valid: false,
                    total_links: self.links.len(),
                    broken_at: Some(i + 1),
                    broken_reason: Some(format!("Data integrity: {}", e)),
                };
            }

            // Verify chain linkage (skip genesis)
            if i > 0 {
                let prev_fp = &self.links[i - 1].f;
                if link.prev.as_deref() != Some(prev_fp.as_str()) {
                    return ChainVerifyResult {
                        valid: false,
                        total_links: self.links.len(),
                        broken_at: Some(i + 1),
                        broken_reason: Some(format!(
                            "Chain broken: link {} doesn't reference link {}",
                            i + 1, i
                        )),
                    };
                }
            }
        }

        ChainVerifyResult {
            valid: true,
            total_links: self.links.len(),
            broken_at: None,
            broken_reason: None,
        }
    }

    /// Get the length of the chain
    pub fn len(&self) -> usize {
        self.links.len()
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Serialize to JSON - safe to store in Redis, Postgres, send anywhere
    pub fn to_json(&self) -> Result<String, UniversalError> {
        serde_json::to_string(self)
            .map_err(|e| UniversalError::MalformedEnvelope(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self, UniversalError> {
        serde_json::from_str(s)
            .map_err(|e| UniversalError::MalformedEnvelope(e.to_string()))
    }

    /// Print a chain report
    pub fn report(&self) -> String {
        let result = self.verify();
        let mut out = String::new();
        out.push_str("━━━━ Entrouter Universal Chain Report ━━━━\n");
        out.push_str(&format!("Links: {} | Valid: {}\n\n", self.links.len(), result.valid));
        for link in &self.links {
            let status = if result.broken_at == Some(link.seq as usize) { "❌" } else { "✅" };
            out.push_str(&format!(
                "  Link {}: {} | ts: {} | fp: {}...\n",
                link.seq, status, link.ts,
                &link.f[..16]
            ));
        }
        if let Some(reason) = &result.broken_reason {
            out.push_str(&format!("\n  ❌ {}\n", reason));
        }
        out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        out
    }
}
