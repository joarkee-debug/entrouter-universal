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
//  Entrouter Universal - Guardian v3
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::{decode_str, encode_str, fingerprint_str};

/// A record of a single checkpoint in the pipeline.
#[derive(Debug, Clone)]
pub struct LayerRecord {
    /// Human-readable name of this pipeline stage.
    pub layer: String,
    /// The Base64-encoded payload at this stage.
    pub encoded: String,
    /// SHA-256 fingerprint computed at this stage.
    pub fingerprint: String,
    /// `true` if the fingerprint still matches the original.
    pub intact: bool,
    /// Decode error message, if the payload could not be decoded.
    pub error: Option<String>,
}

/// Tracks data integrity across multiple pipeline stages.
///
/// Create a `Guardian` with [`Guardian::new`], then call
/// [`Guardian::checkpoint`] after each stage to record whether the
/// data is still intact.
///
/// # Example
///
/// ```
/// use entrouter_universal::Guardian;
///
/// let mut g = Guardian::new("hello");
/// let enc = g.encoded().to_string();
/// g.checkpoint("step-1", &enc);
/// assert!(g.is_intact());
/// ```
#[derive(Debug, Clone)]
pub struct Guardian {
    original_fingerprint: String,
    encoded: String,
    pub layers: Vec<LayerRecord>,
}

impl Guardian {
    /// Create a new guardian for `input`.
    #[must_use]
    pub fn new(input: &str) -> Self {
        Self {
            original_fingerprint: fingerprint_str(input),
            encoded: encode_str(input),
            layers: Vec::new(),
        }
    }

    /// Record a checkpoint, comparing `current_encoded` against the original fingerprint.
    pub fn checkpoint(&mut self, layer_name: &str, current_encoded: &str) {
        match decode_str(current_encoded) {
            Ok(decoded) => {
                let fp = fingerprint_str(&decoded);
                let intact = fp == self.original_fingerprint;
                self.layers.push(LayerRecord {
                    layer: layer_name.to_string(),
                    encoded: current_encoded.to_string(),
                    fingerprint: fp,
                    intact,
                    error: None,
                });
            }
            Err(e) => {
                self.layers.push(LayerRecord {
                    layer: layer_name.to_string(),
                    encoded: current_encoded.to_string(),
                    fingerprint: String::new(),
                    intact: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    /// Returns the Base64-encoded form of the original input.
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Returns the SHA-256 fingerprint of the original input.
    pub fn original_fingerprint(&self) -> &str {
        &self.original_fingerprint
    }

    /// Returns the first checkpoint that failed verification, if any.
    pub fn first_violation(&self) -> Option<&LayerRecord> {
        self.layers.iter().find(|l| !l.intact)
    }

    /// Returns `true` if every checkpoint passed verification.
    pub fn is_intact(&self) -> bool {
        self.layers.iter().all(|l| l.intact)
    }

    /// Panics with a diagnostic message if any checkpoint is violated.
    pub fn assert_intact(&self) {
        if let Some(v) = self.first_violation() {
            panic!(
                "Entrouter Universal: integrity violation at layer '{}'\nExpected: {}\nGot: {}",
                v.layer, self.original_fingerprint, v.fingerprint
            );
        }
    }

    /// Returns a human-readable pipeline integrity report.
    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str("━━━━ Entrouter Universal Pipeline Report ━━━━\n");
        out.push_str(&format!(
            "Original fingerprint: {}\n",
            self.original_fingerprint
        ));
        out.push_str(&format!("Overall intact: {}\n\n", self.is_intact()));
        for (i, layer) in self.layers.iter().enumerate() {
            let status = if layer.intact { "✅" } else { "❌ VIOLATED" };
            out.push_str(&format!(
                "  Layer {}: {} - {}\n",
                i + 1,
                layer.layer,
                status
            ));
            if !layer.intact {
                out.push_str(&format!(
                    "    Expected: {}\n    Got:      {}\n",
                    self.original_fingerprint, layer.fingerprint
                ));
            }
        }
        out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        out
    }
}
