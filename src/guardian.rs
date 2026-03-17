// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal - Guardian v2
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::{encode_str, decode_str, fingerprint_str};

#[derive(Debug, Clone)]
pub struct LayerRecord {
    pub layer:       String,
    pub encoded:     String,
    pub fingerprint: String,
    pub intact:      bool,
}

#[derive(Debug)]
pub struct Guardian {
    original_fingerprint: String,
    encoded:              String,
    pub layers:           Vec<LayerRecord>,
}

impl Guardian {
    pub fn new(input: &str) -> Self {
        Self {
            original_fingerprint: fingerprint_str(input),
            encoded:              encode_str(input),
            layers:               Vec::new(),
        }
    }

    pub fn checkpoint(&mut self, layer_name: &str, current_encoded: &str) {
        let decoded = decode_str(current_encoded).unwrap_or_default();
        let fp      = fingerprint_str(&decoded);
        let intact  = fp == self.original_fingerprint;
        self.layers.push(LayerRecord {
            layer:       layer_name.to_string(),
            encoded:     current_encoded.to_string(),
            fingerprint: fp,
            intact,
        });
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn original_fingerprint(&self) -> &str {
        &self.original_fingerprint
    }

    pub fn first_violation(&self) -> Option<&LayerRecord> {
        self.layers.iter().find(|l| !l.intact)
    }

    pub fn is_intact(&self) -> bool {
        self.layers.iter().all(|l| l.intact)
    }

    pub fn assert_intact(&self) {
        if let Some(v) = self.first_violation() {
            panic!(
                "Entrouter Universal: integrity violation at layer '{}'\nExpected: {}\nGot: {}",
                v.layer, self.original_fingerprint, v.fingerprint
            );
        }
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str("━━━━ Entrouter Universal Pipeline Report ━━━━\n");
        out.push_str(&format!("Original fingerprint: {}\n", self.original_fingerprint));
        out.push_str(&format!("Overall intact: {}\n\n", self.is_intact()));
        for (i, layer) in self.layers.iter().enumerate() {
            let status = if layer.intact { "✅" } else { "❌ VIOLATED" };
            out.push_str(&format!("  Layer {}: {} - {}\n", i + 1, layer.layer, status));
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
