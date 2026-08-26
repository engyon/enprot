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

//! Pure-Rust crypto backend (TODO.complete/65's `wasm` feature, no
//! longer a stub).
//!
//! Replaces the Botan dependency for the two operations the edge
//! path actually needs — SHA3-256 content addressing and
//! AES-256-SIV encryption — with the RustCrypto `sha3` and
//! `aes-siv` crates. The PBKDF (Argon2) and OpenPGP paths still
//! need Botan; the feature is "no Botan for content
//! addressing + SIV", not "no Botan at all".
//!
//! Wired in only behind the `pure-rust-crypto` feature — the
//! default build is unchanged. Tests in this module run when the
//! feature is on; the default CI leg doesn't see them.

use aes_siv::aead::{AeadInPlace, KeyInit};
use aes_siv::{Aes256SivAead, Nonce};

use crate::error::{Error, Result};

/// SHA3-256 hex digest (pure Rust). Wire-compatible with
/// `crypto::hexdigest("sha3-256", …)` — the policy gate is skipped
/// here; the edge path is the policy's default (default-policy
/// ciphers only), and bypassing the policy check is exactly what
/// enables no_std builds.
pub fn sha3_256_hex(data: &[u8]) -> String {
    use sha3::Digest;
    let mut h = sha3::Sha3_256::new();
    h.update(data);
    let out = h.finalize();
    out.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// AES-256-SIV encrypt (pure Rust). Wire-compatible with
/// `cipher::encryption("aes-256-siv")` — same key length (64
/// bytes), same nonce-misuse-resistant construction.
pub fn aes_256_siv_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 64 {
        return Err(Error::InvalidArg {
            arg: "key",
            reason: format!("AES-256-SIV key must be 64 bytes, got {}", key.len()),
        });
    }
    if nonce.len() != 16 {
        return Err(Error::InvalidArg {
            arg: "nonce",
            reason: format!("AES-256-SIV nonce must be 16 bytes, got {}", nonce.len()),
        });
    }
    let cipher = Aes256SivAead::new_from_slice(key).map_err(|_| Error::AeadFailed {
        alg: "aes-256-siv",
        op: "init",
    })?;
    let mut buf = pt.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| Error::AeadFailed {
            alg: "aes-256-siv",
            op: "encrypt",
        })?;
    Ok(buf)
}

/// AES-256-SIV decrypt (pure Rust).
pub fn aes_256_siv_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 64 {
        return Err(Error::InvalidArg {
            arg: "key",
            reason: format!("AES-256-SIV key must be 64 bytes, got {}", key.len()),
        });
    }
    if nonce.len() != 16 {
        return Err(Error::InvalidArg {
            arg: "nonce",
            reason: format!("AES-256-SIV nonce must be 16 bytes, got {}", nonce.len()),
        });
    }
    let cipher = Aes256SivAead::new_from_slice(key).map_err(|_| Error::AeadFailed {
        alg: "aes-256-siv",
        op: "init",
    })?;
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place(Nonce::from_slice(nonce), aad, &mut buf)
        .map_err(|_| Error::AeadFailed {
            alg: "aes-256-siv",
            op: "decrypt",
        })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_known_answer() {
        // FIPS 202 test vector: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        assert_eq!(
            sha3_256_hex(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        // FIPS 202: SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
        assert_eq!(
            sha3_256_hex(b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn aes_256_siv_round_trip_with_various_payloads() {
        let key = [0x42u8; 64];
        let nonce = [0u8; 16]; // RFC 5297 mandates 16 bytes
        for pt in [
            b"".to_vec(),
            b"hello".to_vec(),
            vec![0u8; 4096],
            (0..1024).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
        ] {
            let aad = b"file.aep";
            let ct = aes_256_siv_encrypt(&key, &nonce, aad, &pt).unwrap();
            let rt = aes_256_siv_decrypt(&key, &nonce, aad, &ct).unwrap();
            assert_eq!(pt, rt, "round-trip identity failed for len {}", pt.len());
        }
    }

    #[test]
    fn aes_256_siv_rejects_bad_key_length() {
        let err = aes_256_siv_encrypt(&[0u8; 32], b"n", b"a", b"p").unwrap_err();
        assert!(err.to_string().contains("64 bytes"), "got {err}");
    }
}
