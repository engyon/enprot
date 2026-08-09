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

use phf::phf_map;
use std::collections::BTreeMap;

pub use crate::policy::CryptoPolicy;
pub use crate::policy::default::CryptoPolicyDefault;
pub use crate::policy::nist::CryptoPolicyNIST;

use crate::error::{Error, Result};

/// Factory for the default crypto policy. Eliminates the 35-site
/// `Box::new(CryptoPolicyDefault {})` duplication across cli.rs,
/// kemenc.rs, provenance, scm, merge, resolve, etc. (TODO.roadmap/61.)
pub fn default_policy() -> Box<dyn CryptoPolicy> {
    Box::new(CryptoPolicyDefault {})
}

pub static BOTAN_HASH_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "sha256" => "SHA-256",
    "sha512" => "SHA-512",
    "sha3-256" => "SHA-3(256)",
    "sha3-512" => "SHA-3(512)",
};

fn to_botan_hash(alg: &str) -> Result<&'static str> {
    BOTAN_HASH_ALG_MAP
        .get(alg)
        .copied()
        .ok_or_else(|| Error::InvalidArg {
            arg: "hashalg",
            reason: format!("Unrecognized hash algorithm: {alg}"),
        })
}

pub fn digest(alg: &str, data: &[u8], policy: &dyn CryptoPolicy) -> Result<Vec<u8>> {
    policy.check_hash(alg).map_err(Error::Policy)?;
    let mut hash = botan::HashFunction::new(to_botan_hash(alg)?).map_err(Error::botan)?;
    hash.update(data).map_err(Error::botan)?;
    hash.finish().map_err(Error::botan)
}

pub fn hexdigest(alg: &str, data: &[u8], policy: &dyn CryptoPolicy) -> Result<String> {
    Ok(hex::encode(digest(alg, data, policy)?))
}

/// HKDF using SHA-256. Used by the deterministic AES-GCM variants
/// (issue #39) to domain-separate the PBKDF master key into an encryption
/// key and an IV-derivation key. The single-shot form (`HKDF(SHA-256)`)
/// combines Extract+Expand; passing the PBKDF output as IKM is fine
/// because it's already pseudorandom.
pub fn hkdf_sha256(prk: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    botan::kdf("HKDF(SHA-256)", output_len, prk, &[], info).map_err(Error::botan)
}

/// HMAC-SHA-256. Used to derive the AES-GCM nonce deterministically from
/// the plaintext under the IV-derivation key (issue #39).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = botan::MsgAuthCode::new("HMAC(SHA-256)").map_err(Error::botan)?;
    mac.set_key(key).map_err(Error::botan)?;
    mac.update(data).map_err(Error::botan)?;
    mac.finish().map_err(Error::botan)
}

fn to_botan_pbkdf(alg: &str) -> Result<std::borrow::Cow<'static, str>> {
    if let Some(rest) = alg.strip_prefix("pbkdf2-") {
        return Ok(format!("PBKDF2({})", to_botan_hash(rest)?).into());
    }
    match alg {
        "argon2" => Ok("Argon2id".into()),
        "scrypt" => Ok("Scrypt".into()),
        _ => Err(Error::InvalidArg {
            arg: "--pbkdf",
            reason: format!("Invalid KDF: '{}'", alg),
        }),
    }
}

pub fn derive_key_from_password(
    alg: &str,
    param_order: &[&[&str; 3]; 2],
    key_len: usize,
    password: &str,
    salt: &[u8],
    mut params_map: BTreeMap<String, usize>,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    policy
        .check_pbkdf(alg, key_len, password, salt, &params_map)
        .map_err(Error::Policy)?;
    let mut params: [usize; 3] = [0, 0, 0];
    for (i, param) in param_order[1].iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        params[i] = params_map.remove(*param).ok_or_else(|| Error::InvalidArg {
            arg: "--pbkdf-params",
            reason: format!("Missing PBKDF parameter: {param}"),
        })?;
    }
    if !params_map.is_empty() {
        return Err(Error::InvalidArg {
            arg: "--pbkdf-params",
            reason: format!(
                "Extraneous PBKDF parameters: {}",
                params_map.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        });
    }
    let key = botan::derive_key_from_password(
        &to_botan_pbkdf(alg)?,
        key_len,
        password,
        salt,
        params[0],
        params[1],
        params[2],
    )
    .map_err(Error::botan)?;
    Ok(key)
}

pub fn derive_key_from_password_timed(
    alg: &str,
    param_order: &[&[&str; 3]; 2],
    key_len: usize,
    password: &str,
    salt: &[u8],
    msec: u32,
    policy: &dyn CryptoPolicy,
) -> Result<(Vec<u8>, BTreeMap<String, usize>)> {
    let (key, p1, p2, p3) =
        botan::derive_key_from_password_timed(&to_botan_pbkdf(alg)?, key_len, password, salt, msec)
            .map_err(Error::botan)?;
    let params = [p1, p2, p3];
    let mut params_map = BTreeMap::new();
    for (i, param) in param_order[0].iter().filter(|v| !v.is_empty()).enumerate() {
        params_map.insert((*param).to_string(), params[i]);
    }
    policy
        .check_pbkdf(alg, key_len, password, salt, &params_map)
        .map_err(Error::Policy)?;
    Ok((key, params_map))
}
