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
//  Entrouter Universal - Compression
//
//  Gzip before Base64. Transparent to the consumer.
//  Large payloads shrink before encoding - smaller wire size,
//  same integrity guarantees.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::UniversalError;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

/// Maximum decompressed size (16 MiB) to guard against gzip bombs.
const MAX_DECOMPRESS_SIZE: usize = 16 * 1024 * 1024;

/// Gzip compress bytes
pub fn compress(input: &[u8]) -> Result<Vec<u8>, UniversalError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(input)
        .map_err(|e| UniversalError::CompressError(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| UniversalError::CompressError(e.to_string()))
}

/// Gzip decompress bytes with a size guard against gzip bombs.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, UniversalError> {
    let mut decoder = GzDecoder::new(input);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| UniversalError::CompressError(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() > MAX_DECOMPRESS_SIZE {
            return Err(UniversalError::CompressError(format!(
                "decompressed size exceeds {} byte limit",
                MAX_DECOMPRESS_SIZE
            )));
        }
    }
    Ok(out)
}
