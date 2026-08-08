// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Compression layer (TODO.complete/68).
//!
//! Provides optional deflate compression of plaintext before
//! encryption. The compression algorithm is recorded in the
//! cipher extfield as `compress:zlib` so the decryptor knows to
//! decompress.
//!
//! Security note: compression before encryption can leak plaintext
//! structure via CRIME-style attacks when the attacker can inject
//! chosen plaintext and observe ciphertext sizes. For file-at-rest
//! encryption (enprot's use case), this attack vector requires the
//! attacker to control part of the encrypted content AND observe
//! the ciphertext size — a significantly weaker position than the
//! TLS CRIME attack. Users who are concerned can simply not use
//! `--compress`.

use flate2::Compression;
use flate2::read::{ZlibDecoder, ZlibEncoder};
use std::io::Read;

use crate::error::{Error, Result};

/// Extfield value for zlib compression.
pub const COMPRESS_EXTFIELD: &str = "zlib";

/// Compress plaintext using zlib deflate.
///
/// Only compresses if the compressed form is actually smaller;
/// otherwise returns the original bytes (with no extfield). This
/// avoids wasting space on incompressible data.
pub fn compress(plaintext: &[u8]) -> Result<(Vec<u8>, bool)> {
    let mut encoder = ZlibEncoder::new(plaintext, Compression::default());
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| Error::Io(std::io::Error::other(format!("compression failed: {e}"))))?;
    if compressed.len() < plaintext.len() {
        Ok((compressed, true))
    } else {
        Ok((plaintext.to_vec(), false))
    }
}

/// Decompress data that was compressed with [`compress`].
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| Error::Io(std::io::Error::other(format!("decompression failed: {e}"))))?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_text() {
        let input = b"Hello, World! This is a test of compression. ".repeat(20);
        let (compressed, did_compress) = compress(&input).unwrap();
        assert!(did_compress);
        assert!(compressed.len() < input.len());
        let recovered = decompress(&compressed).unwrap();
        assert_eq!(recovered, input);
    }

    #[test]
    fn round_trip_random_data() {
        // High-entropy data that won't compress well — tests the
        // no-compression path (compress returns original bytes).
        let input: Vec<u8> = (0..1024u32)
            .flat_map(|i| i.wrapping_mul(2654435761).to_le_bytes())
            .take(512)
            .collect();
        let (output, did_compress) = compress(&input).unwrap();
        if did_compress {
            let recovered = decompress(&output).unwrap();
            assert_eq!(recovered, input);
        } else {
            assert_eq!(output, input);
        }
    }

    #[test]
    fn empty_input() {
        let (output, did_compress) = compress(b"").unwrap();
        assert!(!did_compress);
        assert!(output.is_empty());
    }
}
