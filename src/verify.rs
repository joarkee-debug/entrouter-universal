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

/// The result of a verification operation.
///
/// Contains the decoded bytes, their fingerprint, and whether the data
/// passed integrity checks.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyResult {
    /// `true` if the fingerprint matched the original.
    pub intact: bool,
    /// The decoded raw bytes.
    pub decoded: Vec<u8>,
    /// SHA-256 fingerprint of the decoded data.
    pub fingerprint: String,
}

impl std::fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.intact {
            write!(f, "Intact (fp: {}...)", &self.fingerprint[..16])
        } else {
            write!(f, "Violated")
        }
    }
}
