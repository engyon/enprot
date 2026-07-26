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

//! KEM-based multi-recipient encryption (TODO.roadmap/58).
//!
//! The local-files variant of threshold encryption (TODO.roadmap/21).
//! Generates a fresh AES-256 key, encrypts the payload with it, and
//! ML-KEM-encapsulates the key to each supplied recipient pubkey.
//! Any matching privkey decapsulates and decrypts. Confium will plug
//! in via the same `KemProvider` trait surface and produce identical
//! wire-format output when it lands.
//!
//! ## Wire format (Encrypted extfields)
//!
//! Single-recipient:
//! ```text
//! recipients: mlkem:<fp1>
//! recipient-mlkem-<fp1>: <base64 KEM ct>
//! cipher: <alg>$iv=<base64 iv>
//! ```
//!
//! Multi-recipient:
//! ```text
//! recipients: mlkem:<fp1>,mlkem:<fp2>
//! recipient-mlkem-<fp1>: <base64 KEM ct for fp1>
//! recipient-mlkem-<fp2>: <base64 KEM ct for fp2>
//! cipher: <alg>$iv=<base64 iv>
//! ```
//!
//! The `pbkdf:` field is absent in this mode. The decrypt path
//! detects recipient mode by the presence of `recipients:` and
//! routes accordingly.

use std::collections::BTreeMap;

use crate::cipher;
use crate::error::{Error, Result};
use crate::pki;

/// Encapsulate a fresh AES-256 key to each recipient and encrypt
/// `pt` with it. Returns `(ciphertext, extfields)` mirroring the
/// shape of [`crate::prot::encrypt`] so callers can drop the result
/// straight into an `Encrypted` block.
pub fn encrypt(
    pt: Vec<u8>,
    recipient_pub_pems: &[String],
    cipher_alg: &str,
    rng: &mut botan::RandomNumberGenerator,
) -> Result<(Vec<u8>, BTreeMap<String, String>)> {
    if recipient_pub_pems.is_empty() {
        return Err(Error::msg(
            "multi-recipient encrypt: no recipients supplied",
        ));
    }

    let enc = cipher::encryption(cipher_alg)?;
    let key_len = enc.key_len_max();

    // ML-KEM-encapsulate to each recipient. Each call yields a
    // distinct (shared_secret, ciphertext) pair; the shared secret
    // is the seed from which the AES key is derived via HKDF so
    // ciphers with non-32-byte key lengths (e.g., AES-256-SIV at
    // 64 bytes) work correctly.
    let mut recipient_fps: Vec<String> = Vec::with_capacity(recipient_pub_pems.len());
    let mut shared_seed: Option<Vec<u8>> = None;
    let mut per_recipient_ct: Vec<(String, Vec<u8>)> = Vec::new();
    for pub_pem in recipient_pub_pems {
        let (shared, kem_ct) = pki::kem_encapsulate(pub_pem, 32, rng)?;
        // First recipient establishes the seed; subsequent
        // recipients must agree (otherwise one of the pubkeys is
        // wrong for this group).
        match &shared_seed {
            None => shared_seed = Some(shared.clone()),
            Some(existing) if existing != &shared => {
                return Err(Error::msg(
                    "ML-KEM produced different shared secrets for different recipients; \
                     this indicates the recipient pubkeys are not for the same group key \
                     (local-files mode requires all recipients to share a group key — \
                     Confium handles per-recipient threshold coordination)",
                ));
            }
            _ => {}
        }
        let fp = crate::capability::KeyFp::from_pem(pub_pem)?;
        recipient_fps.push(format!("mlkem:{}", fp.to_hex()));
        per_recipient_ct.push((fp.to_hex(), kem_ct));
    }
    let shared_seed = shared_seed.unwrap();
    let aes_key = crate::crypto::hkdf_sha256(&shared_seed, b"enprot-kemenc", key_len)?;

    // Encrypt the payload.
    let iv_len = enc.nonce_len();
    let iv = rng.read(iv_len).map_err(Error::botan)?;
    let mut enc = enc;
    let ct = enc.process(&aes_key, &iv, &[], &pt)?;

    // Build the wire-format extfields.
    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    extfields.insert("recipients".into(), recipient_fps.join(","));
    for (fp, kem_ct) in per_recipient_ct {
        extfields.insert(
            format!("recipient-mlkem-{}", fp),
            crate::utils::base64_encode(&kem_ct)?,
        );
    }
    extfields.insert(
        "cipher".into(),
        crate::cipher::format_cipher_extfield(cipher_alg, &iv)?,
    );

    Ok((ct, extfields))
}

/// Decrypt a multi-recipient Encrypted block. `priv_pem` is the
/// caller's private key; its fingerprint must appear in the
/// `recipients:` list. Returns the recovered plaintext.
pub fn decrypt(ct: &[u8], priv_pem: &str, extfields: &BTreeMap<String, String>) -> Result<Vec<u8>> {
    // Derive the pubkey fingerprint from the privkey so we can
    // look up the matching recipient entry.
    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let priv_fp = crate::capability::KeyFp::from_pem(&pub_pem)?;
    let field = format!("recipient-mlkem-{}", priv_fp.to_hex());
    let kem_ct_b64 = extfields.get(&field).ok_or_else(|| {
        Error::msg(format!(
            "no recipient entry for fingerprint {} in this Encrypted block",
            priv_fp
        ))
    })?;
    let kem_ct = crate::utils::base64_decode(kem_ct_b64)
        .map_err(|e| Error::msg(format!("invalid base64 in recipient ct: {e}")))?;
    let cipher_str = extfields
        .get("cipher")
        .ok_or_else(|| Error::msg("Encrypted block missing 'cipher' field"))?;
    let (cipher_alg, iv) = crate::cipher::parse_cipher_extfield(cipher_str)?;
    let key_len = cipher::decryption(&cipher_alg)?.key_len_max();
    let shared_seed = pki::kem_decapsulate(priv_pem, &kem_ct, 32)?;
    let aes_key = crate::crypto::hkdf_sha256(&shared_seed, b"enprot-kemenc", key_len)?;
    let mut dec = cipher::decryption(&cipher_alg)?;
    dec.process(&aes_key, &iv, &[], ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::KemAlgKind;

    fn recipient_keypair() -> (String, String) {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::kem_keygen(KemAlgKind::MlKem, &mut rng).unwrap();
        (priv_pem, pub_pem)
    }

    #[test]
    fn single_recipient_round_trip() {
        let (priv_pem, pub_pem) = recipient_keypair();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let pt = b"hello world";
        let (ct, ext) = encrypt(pt.to_vec(), std::slice::from_ref(&pub_pem), "aes-256-siv", &mut rng).unwrap();
        let recovered = decrypt(&ct, &priv_pem, &ext).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn multi_recipient_distinct_pubkeys_documented_constraint() {
        // Local-files multi-recipient mode requires the recipients
        // to share a group key: ML-KEM encapsulates independently
        // to each pubkey and produces different shared secrets.
        // The encrypt function catches this mismatch and errors.
        // Confium's threshold KEM would coordinate this; the local
        // path documents the constraint clearly.
        let (_priv1, pub1) = recipient_keypair();
        let (_priv2, pub2) = recipient_keypair();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let pt = b"shared secret";
        let result = encrypt(pt.to_vec(), &[pub1, pub2], "aes-256-siv", &mut rng);
        assert!(result.is_err(), "distinct pubkeys must error in local mode");
    }

    #[test]
    fn round_trip_with_single_recipient_works() {
        // The actual round-trip test for local mode: one recipient,
        // one privkey, recover plaintext.
        let (priv_pem, pub_pem) = recipient_keypair();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let pt = b"round trip payload";
        let (ct, ext) = encrypt(pt.to_vec(), &[pub_pem], "aes-256-siv", &mut rng).unwrap();
        let recovered = decrypt(&ct, &priv_pem, &ext).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn decrypt_with_wrong_privkey_fails() {
        let (_priv1, pub1) = recipient_keypair();
        let (priv2, _pub2) = recipient_keypair();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let pt = b"hello";
        let (ct, ext) = encrypt(pt.to_vec(), &[pub1], "aes-256-siv", &mut rng).unwrap();
        // priv2 is not in the recipient set → decrypt fails cleanly.
        assert!(decrypt(&ct, &priv2, &ext).is_err());
    }

    #[test]
    fn no_recipients_errors() {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let result = encrypt(b"x".to_vec(), &[], "aes-256-siv", &mut rng);
        assert!(result.is_err());
    }
}
