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

use phf::phf_set;
use std::collections::BTreeMap;

use crate::policy::CryptoPolicy;
use crate::policy::default::CryptoPolicyDefault;

pub struct CryptoPolicyNIST {}

/// Categories of cryptographic algorithm the NIST policy distinguishes.
/// Replaces the stringly-typed `kind: &str` parameter the previous
/// implementation used so the compiler enforces exhaustive matching.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AlgKind {
    Cipher,
    Hash,
    Pbkdf,
}

impl AlgKind {
    fn approved_set(self) -> &'static phf::Set<&'static str> {
        match self {
            Self::Cipher => &CryptoPolicyNIST::NIST_APPROVED_CIPHERS,
            Self::Hash => &CryptoPolicyNIST::NIST_APPROVED_HASHES,
            Self::Pbkdf => &CryptoPolicyNIST::NIST_APPROVED_PBKDFS,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Cipher => "Cipher",
            Self::Hash => "Hash",
            Self::Pbkdf => "PBKDF",
        }
    }

    fn is_approved(self, alg: &str) -> Result<(), String> {
        if self.approved_set().contains(alg) {
            Ok(())
        } else {
            Err(format!(
                "{} algorithm is not permitted by policy: {}",
                self.label(),
                alg
            ))
        }
    }
}

impl CryptoPolicyNIST {
    const DEFAULT_PBKDF_ALG: &'static str = "pbkdf2-sha512";
    const DEFAULT_PBKDF_SALT_LEN: usize = 32;
    const DEFAULT_PBKDF_MSEC: u32 = CryptoPolicyDefault::DEFAULT_PBKDF_MSEC;
    const DEFAULT_CIPHER_ALG: &'static str = "aes-256-gcm";
    const NIST_PBKDF_MIN_SALT_LEN: usize = 16;

    const NIST_APPROVED_PBKDFS: phf::Set<&'static str> = phf_set! {
        "pbkdf2-sha256",
        "pbkdf2-sha512",
    };
    const NIST_APPROVED_CIPHERS: phf::Set<&'static str> = phf_set! {
        "aes-256-gcm",
    };
    const NIST_APPROVED_HASHES: phf::Set<&'static str> = phf_set! {
        "sha3-256",
        "sha3-512",
    };
}

impl CryptoPolicy for CryptoPolicyNIST {
    fn check_hash(&self, alg: &str) -> Result<(), String> {
        AlgKind::Hash.is_approved(alg)
    }

    fn check_pbkdf(
        &self,
        alg: &str,
        key_len: usize,
        _password: &str,
        salt: &[u8],
        params: &BTreeMap<String, usize>,
    ) -> Result<(), String> {
        AlgKind::Pbkdf.is_approved(alg)?;
        if salt.len() < Self::NIST_PBKDF_MIN_SALT_LEN {
            return Err("Salt length violates policy".to_string());
        }
        if key_len < 14 {
            return Err("Key length violates policy".to_string());
        }
        if let Some(iters) = params.get("i")
            && *iters < 1000
        {
            return Err("Iteration count violates policy".to_string());
        }
        Ok(())
    }

    fn check_cipher_alg(&self, alg: &str) -> Result<(), String> {
        // Strip the `-det` suffix used by the deterministic AES-GCM variants
        // before delegating; the underlying cipher backend is the same.
        self.check_cipher_alg_impl(alg.trim_end_matches("-det"))
    }

    fn check_cipher_alg_impl(&self, alg: &str) -> Result<(), String> {
        AlgKind::Cipher.is_approved(alg)
    }

    fn check_cipher(&self, alg: &str, _key: &[u8], iv: &[u8], _ad: &[u8]) -> Result<(), String> {
        let base = alg.trim_end_matches("-det");
        AlgKind::Cipher.is_approved(base)?;
        if base == "aes-256-gcm" && iv.len() != 96 / 8 {
            return Err(
                "IV length does not match NIST recommendations for this cipher.".to_string(),
            );
        }
        Ok(())
    }

    fn default_pbkdf_alg(&self) -> String {
        Self::DEFAULT_PBKDF_ALG.to_string()
    }

    fn default_pbkdf_salt_length(&self) -> usize {
        Self::DEFAULT_PBKDF_SALT_LEN
    }

    fn default_pbkdf_millis(&self) -> u32 {
        Self::DEFAULT_PBKDF_MSEC
    }

    fn default_cipher_alg(&self) -> String {
        Self::DEFAULT_CIPHER_ALG.to_string()
    }
}
