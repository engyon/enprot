// Copyright (c) 2019-2020 [Ribose Inc](https://www.ribose.com).
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

use policy::default::CryptoPolicyDefault;
use policy::CryptoPolicy;

pub struct CryptoPolicyNIST {}

impl CryptoPolicyNIST {
    const DEFAULT_PBKDF_ALG: &'static str = "pbkdf2-sha512";
    const DEFAULT_PBKDF_SALT_LEN: usize = 32;
    // no policy per se, so copy the default policy setting
    const DEFAULT_PBKDF_MSEC: u32 = CryptoPolicyDefault::DEFAULT_PBKDF_MSEC;
    const DEFAULT_CIPHER_ALG: &'static str = "aes-256-gcm";
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
    const NIST_PBKDF_MIN_SALT_LEN: usize = 16;

    fn check_alg(&self, kind: &str, alg: &str) -> Result<(), &'static str> {
        let lst = match kind {
            "Cipher" => &Self::NIST_APPROVED_CIPHERS,
            "Hash" => &Self::NIST_APPROVED_HASHES,
            "PBKDF" => &Self::NIST_APPROVED_PBKDFS,
            _ => return Err("Invalid algorithm kind"),
        };
        if lst.contains(alg) {
            Ok(())
        } else {
            eprintln!("{} algorithm is not permitted by policy: {}", kind, alg);
            Err("Algorithm not permitted by policy")
        }
    }
}

impl CryptoPolicy for CryptoPolicyNIST {
    fn check_hash(&self, alg: &str) -> Result<(), &'static str> {
        self.check_alg("Hash", alg)
    }

    fn check_pbkdf(
        &self,
        alg: &str,
        key_len: usize,
        _password: &str,
        salt: &[u8],
        params: &BTreeMap<String, usize>,
    ) -> Result<(), &'static str> {
        self.check_alg("PBKDF", alg)?;
        if salt.len() < Self::NIST_PBKDF_MIN_SALT_LEN {
            return Err("Salt length violates policy");
        }
        if key_len < 14 {
            return Err("Key length violates policy");
        }
        if let Some(iters) = params.get("i") {
            if *iters < 1000 {
                return Err("Iteration count violates policy");
            }
        }
        Ok(())
    }

    fn check_cipher(
        &self,
        alg: &str,
        _key: &[u8],
        iv: &[u8],
        _ad: &[u8],
    ) -> Result<(), &'static str> {
        self.check_alg("Cipher", alg)?;
        if alg == "aes-256-gcm" && iv.len() != 96 / 8 {
            return Err("IV length does not match NIST recommendations for this cipher.");
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
