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

//! Property-based round-trip tests for `prot::encrypt` + `prot::decrypt`.
//!
//! The deterministic AES-GCM-SIV variant (`aes-256-gcm-siv-det`) makes
//! encryption reproducible: same `(password, plaintext)` always
//! produces the same ciphertext. The properties checked are:
//!
//! 1. **Round-trip.** `decrypt(encrypt(pt, password)) = pt` for any
//!    plaintext up to 4 KiB and any alphanumeric password up to 64
//!    chars.
//! 2. **Determinism.** Two encrypts of the same `(password, plaintext)`
//!    produce the same ciphertext. This is the property that lets
//!    `ENCRYPTED` segments deduplicate in the CAS.

use std::collections::BTreeMap;

use proptest::prelude::*;

use enprot::crypto::{CryptoPolicy, CryptoPolicyDefault};
use enprot::etree::{CipherOptions, PBKDFOptions};
use enprot::prot::{decrypt, encrypt};

fn policy() -> Box<dyn CryptoPolicy> {
    Box::new(CryptoPolicyDefault {})
}

fn new_rng() -> Option<botan::RandomNumberGenerator> {
    Some(botan::RandomNumberGenerator::new().unwrap())
}

fn pbkdf_opts() -> PBKDFOptions {
    // PBKDF2 with a fixed salt + 1000 iterations keeps the test fast
    // and deterministic. The crypto surface under test is the cipher
    // round-trip; the KDF parameters don't matter for the property.
    let mut params = BTreeMap::new();
    params.insert("i".to_string(), 1000);
    PBKDFOptions {
        alg: "pbkdf2-sha256".to_string(),
        saltlen: 0,
        salt: Some(b"01234567".to_vec()),
        msec: None,
        params: Some(params),
    }
}

fn cipher_opts(alg: &str) -> CipherOptions {
    CipherOptions {
        alg: alg.to_string(),
        iv: None,
    }
}

fn round_trip_with(pt: &[u8], password: &str, alg: &str) -> Vec<u8> {
    let policy = policy();
    let mut cache: Option<Vec<_>> = Some(Vec::new());

    let (ct, extfields) = encrypt(
        pt.to_vec(),
        password,
        &mut new_rng(),
        &pbkdf_opts(),
        &cipher_opts(alg),
        &mut cache,
        &*policy,
    )
    .expect("encrypt");

    decrypt(
        ct,
        password,
        &extfields.get("pbkdf"),
        &extfields.get("cipher"),
        &mut cache,
        &*policy,
    )
    .expect("decrypt")
}

fn encrypt_with(pt: &[u8], password: &str, alg: &str) -> Vec<u8> {
    let policy = policy();
    let mut cache: Option<Vec<_>> = Some(Vec::new());
    let (ct, _) = encrypt(
        pt.to_vec(),
        password,
        &mut new_rng(),
        &pbkdf_opts(),
        &cipher_opts(alg),
        &mut cache,
        &*policy,
    )
    .expect("encrypt");
    ct
}

proptest! {
    /// `decrypt(encrypt(pt, password)) == pt` for the deterministic
    /// AES-GCM-SIV variant (RustCrypto backend).
    #[test]
    fn round_trip_aes_256_gcm_siv_det(
        pt in prop::collection::vec(any::<u8>(), 0..4096),
        password in "[a-zA-Z0-9]{1,64}",
    ) {
        let recovered = round_trip_with(&pt, &password, "aes-256-gcm-siv-det");
        prop_assert_eq!(recovered, pt);
    }

    /// Same round-trip property for the deterministic AES-GCM variant
    /// (Botan backend).
    #[test]
    fn round_trip_aes_256_gcm_det(
        pt in prop::collection::vec(any::<u8>(), 0..4096),
        password in "[a-zA-Z0-9]{1,64}",
    ) {
        let recovered = round_trip_with(&pt, &password, "aes-256-gcm-det");
        prop_assert_eq!(recovered, pt);
    }

    /// `encrypt(pt, password) == encrypt(pt, password)` — two runs of
    /// the deterministic variant over the same input produce the same
    /// ciphertext. (Random-IV variants would NOT satisfy this; that's
    /// the point of the deterministic mode.)
    #[test]
    fn determinism_aes_256_gcm_siv_det(
        pt in prop::collection::vec(any::<u8>(), 0..1024),
        password in "[a-zA-Z0-9]{1,32}",
    ) {
        let ct_a = encrypt_with(&pt, &password, "aes-256-gcm-siv-det");
        let ct_b = encrypt_with(&pt, &password, "aes-256-gcm-siv-det");
        prop_assert_eq!(ct_a, ct_b, "deterministic mode must produce identical ciphertexts");
    }
}
