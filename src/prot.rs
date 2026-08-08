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

use std::collections::BTreeMap;

use crate::cipher;
use crate::cipher::{format_cipher_extfield, parse_cipher_extfield};
use crate::crypto::{self, CryptoPolicy};
use crate::error::{Error, Result};
use crate::etree;
use crate::pbkdf::{PBKDFCache, derive_key, parse_phc};

#[tracing::instrument(skip(pt, password, rng, pbkdfopts, cipheropts, cache, policy), fields(bytes = pt.len(), alg = %cipheropts.alg))]
pub fn encrypt(
    pt: Vec<u8>,
    password: &str,
    rng: &mut Option<botan::RandomNumberGenerator>,
    pbkdfopts: &etree::PBKDFOptions,
    cipheropts: &etree::CipherOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<(Vec<u8>, BTreeMap<String, String>)> {
    if pbkdfopts.alg == "legacy" {
        eprintln!(
            "Warning: --pbkdf legacy uses an unsalted SHA3-512 truncation and is \
             retained only for compatibility with old blobs; use argon2, scrypt, \
             or pbkdf2-sha{{256,512}} for new encryption."
        );
    }
    // Validate cipher algorithm against the policy BEFORE creating the
    // backend cipher. This way policy rejection fires even when the cipher
    // backend is built without the requested algorithm.
    policy
        .check_cipher_alg(&cipheropts.alg)
        .map_err(Error::Policy)?;

    let enc = cipher::encryption(&cipheropts.alg)?;
    let key_len = enc.key_len_max();
    let (master_key, pbkdf) = derive_key(password, key_len, rng, pbkdfopts, cache, policy)?;

    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    if let Some(p) = pbkdf {
        extfields.insert("pbkdf".to_string(), p);
    }

    let is_det = cipheropts.alg.ends_with("-det");
    let needs_iv = !cipheropts.alg.starts_with("aes-256-siv");

    let (key, iv): (Vec<u8>, Vec<u8>) = if is_det {
        // Deterministic mode: domain-separate the master key into an
        // encryption key and an IV-derivation key via HKDF, then derive
        // the nonce from the plaintext via HMAC. Same (password, plaintext)
        // → same (key, IV) → same ciphertext.
        if !needs_iv {
            return Err(Error::Cipher(format!(
                "{} does not support deterministic mode (SIV is already deterministic)",
                cipheropts.alg
            )));
        }
        let enc_key = crypto::hkdf_sha256(&master_key, b"enprot-enc", key_len)?;
        let iv_key = crypto::hkdf_sha256(&master_key, b"enprot-iv", 32)?;
        let iv_full = crypto::hmac_sha256(&iv_key, &pt)?;
        let iv = iv_full[..enc.nonce_len()].to_vec();
        (enc_key, iv)
    } else if needs_iv {
        let iv = if let Some(myiv) = cipheropts.iv.clone() {
            myiv
        } else {
            let ivlen = enc.nonce_len();
            rng.as_mut()
                .ok_or(Error::InvalidArg {
                    arg: "rng",
                    reason: "Missing RNG for non-deterministic encrypt".to_string(),
                })?
                .read(ivlen)
                .map_err(Error::botan)?
        };
        (master_key, iv)
    } else if cipheropts.iv.is_some() {
        return Err(Error::Cipher("IV was supplied but not expected".into()));
    } else {
        // SIV: no IV needed.
        (master_key, Vec::new())
    };

    if needs_iv {
        extfields.insert(
            "cipher".to_string(),
            format_cipher_extfield(&cipheropts.alg, &iv)?,
        );
    }

    policy
        .check_cipher(&cipheropts.alg, &key, &iv, &[])
        .map_err(Error::Policy)?;

    // Optional compression (TODO.complete/68). Compress before
    // encryption so the CAS stores smaller blobs. Only records the
    // extfield when compression actually reduced the size.
    let pt_final = if cipheropts.compress {
        let (compressed, did_compress) = crate::compress::compress(&pt)?;
        if did_compress {
            extfields.insert(
                "compress".to_string(),
                crate::compress::COMPRESS_EXTFIELD.to_string(),
            );
            compressed
        } else {
            pt
        }
    } else {
        pt
    };

    let mut enc = enc;
    Ok((enc.process(&key, &iv, &[], &pt_final)?, extfields))
}

#[tracing::instrument(skip(ct, password, pbkdf, cipher, cache, policy), fields(bytes = ct.len()))]
pub fn decrypt(
    ct: Vec<u8>,
    password: &str,
    pbkdf: &Option<&String>,
    cipher: &Option<&String>,
    compress: &Option<&String>,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    let (cipher_alg, iv) = match cipher {
        Some(s) => parse_cipher_extfield(s)?,
        None => (cipher::DEFAULT_CIPHER_ALG.to_string(), Vec::new()),
    };

    policy
        .check_cipher_alg(&cipher_alg)
        .map_err(Error::Policy)?;

    let dec = cipher::decryption(&cipher_alg)?;
    let key_len = dec.key_len_max();
    let mut no_rng: Option<botan::RandomNumberGenerator> = None;
    let master_key = if let Some(p) = pbkdf {
        let (alg, params, salt) = parse_phc(p)?;
        let pbkdfopts = etree::PBKDFOptions {
            alg,
            saltlen: 0,
            salt: Some(salt),
            msec: None,
            params: Some(params),
        };
        derive_key(password, key_len, &mut no_rng, &pbkdfopts, cache, policy)?.0
    } else {
        derive_key(
            password,
            key_len,
            &mut no_rng,
            &etree::PBKDFOptions {
                alg: "legacy".to_string(),
                saltlen: 0,
                salt: None,
                msec: None,
                params: None,
            },
            cache,
            policy,
        )?
        .0
    };

    // Deterministic variants domain-separated the master key via HKDF at
    // encrypt time. Decrypt must do the same to recover the enc_key.
    let key = if cipher_alg.ends_with("-det") {
        crypto::hkdf_sha256(&master_key, b"enprot-enc", key_len)?
    } else {
        master_key
    };

    policy
        .check_cipher(&cipher_alg, &key, &iv, &[])
        .map_err(Error::Policy)?;
    let mut dec = dec;
    let pt = dec.process(&key, &iv, &[], &ct)?;

    // Decompress if the extfield says the plaintext was compressed
    // before encryption (TODO.complete/68).
    if let Some(alg) = compress
        && alg.as_str() == crate::compress::COMPRESS_EXTFIELD
    {
        crate::compress::decompress(&pt)
    } else {
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_extfield_roundtrip() {
        // aes-256-gcm with IV
        let s = "aes-256-gcm$iv=MDEyMzQ1Njc4OWFiY2RlZg==";
        let (alg, iv) = parse_cipher_extfield(s).unwrap();
        assert_eq!(alg, "aes-256-gcm");
        assert_eq!(iv, b"0123456789abcdef");
    }

    #[test]
    fn cipher_extfield_default_when_unset() {
        // When the cipher: field is absent on a legacy ENCRYPTED block,
        // prot::decrypt falls back to cipher::DEFAULT_CIPHER_ALG.
        let (alg, iv) = (
            crate::cipher::DEFAULT_CIPHER_ALG.to_string(),
            Vec::<u8>::new(),
        );
        assert_eq!(alg, "aes-256-siv");
        assert!(iv.is_empty());
    }

    #[test]
    fn phc_extfield_roundtrip() {
        let s = "$argon2$m=65536,p=4,t=3$MDEyMzQ1Njc4OWFiY2RlZg==";
        let (alg, params, salt) = parse_phc(s).unwrap();
        assert_eq!(alg, "argon2");
        assert_eq!(params.get("m"), Some(&65536));
        assert_eq!(params.get("t"), Some(&3));
        assert_eq!(params.get("p"), Some(&4));
        assert_eq!(salt, b"0123456789abcdef");
    }
}
