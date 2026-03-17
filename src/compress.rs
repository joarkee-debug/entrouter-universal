// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Entrouter Universal - Compression
//
//  Gzip before Base64. Transparent to the consumer.
//  Large payloads shrink before encoding - smaller wire size,
//  same integrity guarantees.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use std::io::{Write, Read};
use crate::UniversalError;

/// Gzip compress bytes
pub fn compress(input: &[u8]) -> Result<Vec<u8>, UniversalError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input)
        .map_err(|e| UniversalError::CompressError(e.to_string()))?;
    encoder.finish()
        .map_err(|e| UniversalError::CompressError(e.to_string()))
}

/// Gzip decompress bytes
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, UniversalError> {
    let mut decoder = GzDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)
        .map_err(|e| UniversalError::CompressError(e.to_string()))?;
    Ok(out)
}
