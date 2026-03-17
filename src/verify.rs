/// The result of a verification operation.
///
/// Contains the decoded bytes, their fingerprint, and whether the data
/// passed integrity checks.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyResult {
    /// `true` if the fingerprint matched the original.
    pub intact:      bool,
    /// The decoded raw bytes.
    pub decoded:     Vec<u8>,
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
