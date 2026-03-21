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
//  Entrouter Universal - Per-Field Struct Wrapping
//
//  Wraps every field of a struct individually.
//  If Redis mangles just one field, you know exactly which one.
//
//  Usage:
//    let wrapped = UniversalStruct::wrap_fields(vec![
//        ("token",   "abc123..."),
//        ("user_id", "john"),
//        ("amount",  "99.99"),
//    ]);
//
//    let result = wrapped.verify_all();
//    // tells you exactly which field got touched
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::{decode_str, encode_str, fingerprint_str, UniversalError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single field wrapped with its Base64 encoding and SHA-256 fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedField {
    /// Field name
    pub name: String,
    /// Base64 encoded value
    pub d: String,
    /// SHA-256 fingerprint of original value
    pub f: String,
}

impl WrappedField {
    /// Wrap a named value, producing its Base64 encoding and fingerprint.
    pub fn wrap(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            d: encode_str(value),
            f: fingerprint_str(value),
        }
    }

    /// Decode and verify this field, returning the original value on success.
    pub fn verify(&self) -> Result<String, UniversalError> {
        let decoded = decode_str(&self.d)?;
        let actual_fp = fingerprint_str(&decoded);
        if actual_fp != self.f {
            return Err(UniversalError::IntegrityViolation {
                expected: self.f.clone(),
                actual: actual_fp,
            });
        }
        Ok(decoded)
    }

    /// Returns `true` if verification passes.
    pub fn is_intact(&self) -> bool {
        self.verify().is_ok()
    }
}

/// A collection of individually-wrapped fields.
///
/// Each field carries its own Base64 encoding and SHA-256 fingerprint,
/// so a single corrupted field can be identified without re-verifying
/// the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalStruct {
    pub fields: Vec<WrappedField>,
}

/// Per-field verification result.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldVerifyResult {
    /// The field name.
    pub name: String,
    /// `true` if the field passed integrity verification.
    pub intact: bool,
    /// The decoded value, if verification succeeded.
    pub value: Option<String>,
    /// Error message, if verification failed.
    pub error: Option<String>,
}

impl std::fmt::Display for FieldVerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.intact {
            write!(f, "{}: Intact", self.name)
        } else {
            write!(
                f,
                "{}: Violated ({})",
                self.name,
                self.error.as_deref().unwrap_or("unknown")
            )
        }
    }
}

/// Aggregated result of verifying every field in a [`UniversalStruct`].
#[derive(Debug, Clone, PartialEq)]
pub struct StructVerifyResult {
    /// `true` if every field passed verification.
    pub all_intact: bool,
    /// Individual per-field results.
    pub fields: Vec<FieldVerifyResult>,
    /// Names of fields that failed verification.
    pub violations: Vec<String>,
}

impl std::fmt::Display for StructVerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.all_intact {
            write!(f, "All {} fields intact", self.fields.len())
        } else {
            write!(f, "Violations in: {}", self.violations.join(", "))
        }
    }
}

impl UniversalStruct {
    /// Wrap a list of (name, value) field pairs
    #[must_use]
    pub fn wrap_fields(fields: &[(&str, &str)]) -> Self {
        Self {
            fields: fields
                .iter()
                .map(|(name, value)| WrappedField::wrap(name, value))
                .collect(),
        }
    }

    /// Verify all fields - returns detailed per-field results
    pub fn verify_all(&self) -> StructVerifyResult {
        let mut all_intact = true;
        let mut violations = Vec::new();
        let fields = self
            .fields
            .iter()
            .map(|f| match f.verify() {
                Ok(value) => FieldVerifyResult {
                    name: f.name.clone(),
                    intact: true,
                    value: Some(value),
                    error: None,
                },
                Err(e) => {
                    all_intact = false;
                    violations.push(f.name.clone());
                    FieldVerifyResult {
                        name: f.name.clone(),
                        intact: false,
                        value: None,
                        error: Some(e.to_string()),
                    }
                }
            })
            .collect();

        StructVerifyResult {
            all_intact,
            fields,
            violations,
        }
    }

    /// Get a verified field value by name
    pub fn get(&self, name: &str) -> Result<String, UniversalError> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| {
                UniversalError::MalformedEnvelope(format!("field '{}' not found", name))
            })?
            .verify()
    }

    /// Get all verified fields as a HashMap
    pub fn to_map(&self) -> Result<HashMap<String, String>, UniversalError> {
        let result = self.verify_all();
        if !result.all_intact {
            return Err(UniversalError::IntegrityViolation {
                expected: "all fields intact".to_string(),
                actual: format!("violations in: {}", result.violations.join(", ")),
            });
        }
        Ok(result
            .fields
            .into_iter()
            .filter_map(|f| f.value.map(|v| (f.name, v)))
            .collect())
    }

    /// Assert all fields intact - panics with field names if violated
    pub fn assert_intact(&self) {
        let result = self.verify_all();
        if !result.all_intact {
            panic!(
                "Entrouter Universal: field integrity violations in: {}",
                result.violations.join(", ")
            );
        }
    }

    /// Print a full field report
    pub fn report(&self) -> String {
        let result = self.verify_all();
        let mut out = String::new();
        out.push_str("━━━━ Entrouter Universal Field Report ━━━━\n");
        out.push_str(&format!("All intact: {}\n\n", result.all_intact));
        for field in &result.fields {
            let status = if field.intact { "✅" } else { "❌ VIOLATED" };
            out.push_str(&format!(
                "  {}: {} - {}\n",
                field.name,
                status,
                field.value.as_deref().unwrap_or("-")
            ));
            if let Some(err) = &field.error {
                out.push_str(&format!("    Error: {}\n", err));
            }
        }
        out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        out
    }

    /// Serialize this struct to a JSON string.
    pub fn to_json(&self) -> Result<String, UniversalError> {
        serde_json::to_string(self).map_err(|e| UniversalError::SerializationError(e.to_string()))
    }

    /// Deserialize a struct from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, UniversalError> {
        serde_json::from_str(s).map_err(|e| UniversalError::SerializationError(e.to_string()))
    }
}
