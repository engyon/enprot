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

use crate::crypto;
use crate::crypto::CryptoPolicy;
use crate::error::{Error, Result};
use crate::etree;
use crate::utils;

/// For each supported PBKDF algorithm, two orderings of the three numeric
/// parameters Botan accepts: the first is what `derive_key_from_password_timed`
/// returns (in the order Botan produces them), the second is what
/// `derive_key_from_password` consumes when reading them back from a PHC
/// string.
pub static BOTAN_PBKDF_PARAM_MAP: phf::Map<&'static str, &[&[&str; 3]; 2]> = phf_map! {
    // alg              timed()                        manual()
    "argon2"        => &[&["t", "p", "m"],            &["m", "t", "p"]],
    "scrypt"        => &[&["r", "p", "ln"],           &["ln", "r", "p"]],
    "pbkdf2-sha256" => &[&["i", "", ""],              &["i", "", ""]],
    "pbkdf2-sha512" => &[&["i", "", ""],              &["i", "", ""]],
};

pub struct PBKDFCacheEntry {
    pub password: String,
    pub alg: String,
    pub msec: u32,
    pub salt: Vec<u8>,
    pub key: Vec<u8>,
    pub params: BTreeMap<String, usize>,
}
pub type PBKDFCache = Vec<PBKDFCacheEntry>;

fn pbkdf_legacy(password: &str, key_len: usize, policy: &dyn CryptoPolicy) -> Result<Vec<u8>> {
    policy
        .check_pbkdf("sha3-512", key_len, password, &[], &BTreeMap::new())
        .map_err(Error::Policy)?;
    let mut result = crypto::digest("sha3-512", password.as_bytes(), policy)?;
    result.truncate(key_len);
    Ok(result)
}

fn pbkdf_timed(
    alg: &str,
    botan_param_order: &[&[&str; 3]; 2],
    password: &str,
    salt: &[u8],
    msec: u32,
    key_len: usize,
    policy: &dyn CryptoPolicy,
) -> Result<(Vec<u8>, BTreeMap<String, usize>)> {
    crypto::derive_key_from_password_timed(
        alg,
        botan_param_order,
        key_len,
        password,
        salt,
        msec,
        policy,
    )
}

fn pbkdf_manual(
    alg: &str,
    botan_param_order: &[&[&str; 3]; 2],
    password: &str,
    salt: &[u8],
    params_map: BTreeMap<String, usize>,
    key_len: usize,
    policy: &dyn CryptoPolicy,
) -> Result<Vec<u8>> {
    crypto::derive_key_from_password(
        alg,
        botan_param_order,
        key_len,
        password,
        salt,
        params_map,
        policy,
    )
}

/// Serialize a PHC-format string. Layout: `$<id>$<k=v,k=v>$<b64-salt>`.
/// `params` must be sorted by the BTreeMap iteration order (alphabetical).
pub fn format_phc(alg: &str, params: &BTreeMap<String, usize>, salt: &[u8]) -> Result<String> {
    let body = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join(",");
    Ok(format!("${}${}${}", alg, body, utils::base64_encode(salt)?))
}

/// Parse a PHC-format string into its algorithm id, named parameters, and
/// raw salt bytes. The salt may use any character legal in standard base64
/// (including `=` padding); we round-trip through Botan's base64 codec.
///
/// Layout: `$<id>$<k=v,k=v,...>$<b64-salt>`
pub fn parse_phc(s: &str) -> Result<(String, BTreeMap<String, usize>, Vec<u8>)> {
    let body = s
        .strip_prefix('$')
        .ok_or_else(|| Error::Phc("PHC string must start with '$'".into()))?;
    let mut parts = body.splitn(3, '$');
    let id = parts.next().unwrap_or("");
    if id.is_empty() {
        return Err(Error::Phc("PHC string is missing the algorithm id".into()));
    }
    let raw_params = parts.next().unwrap_or("");
    let raw_salt = parts
        .next()
        .ok_or_else(|| Error::Phc("PHC string is missing the salt segment".into()))?;

    let mut params = BTreeMap::new();
    for kv in raw_params.split(',').filter(|s| !s.is_empty()) {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| Error::Phc(format!("PHC param '{}' is not key=value", kv)))?;
        let n: usize = v
            .parse()
            .map_err(|_| Error::Phc(format!("PHC param '{}' has non-numeric value", kv)))?;
        params.insert(k.to_string(), n);
    }

    let salt = utils::base64_decode(raw_salt)?;
    Ok((id.to_string(), params, salt))
}

pub fn derive_key(
    password: &str,
    key_len: usize,
    rng: &mut Option<botan::RandomNumberGenerator>,
    opts: &etree::PBKDFOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &dyn CryptoPolicy,
) -> Result<(Vec<u8>, Option<String>)> {
    if opts.alg == "legacy" {
        return Ok((pbkdf_legacy(password, key_len, policy)?, None));
    }

    let mut salt = match opts.salt.clone() {
        Some(s) => s,
        None => {
            let r = rng
                .as_mut()
                .ok_or_else(|| Error::Pbkdf("PBKDF requires an RNG to generate salt".into()))?;
            r.read(opts.saltlen)
                .map_err(|e| Error::Pbkdf(format!("RNG failure during salt generation: {e}")))?
        }
    };

    let botan_param_order = BOTAN_PBKDF_PARAM_MAP
        .get(opts.alg.as_str())
        .ok_or_else(|| Error::Pbkdf(format!("Missing PBKDF param mapping for '{}'", opts.alg)))?;

    if let Some(params) = opts.params.as_ref() {
        let key = if let Some(entry) = cache.as_ref().unwrap_or(&Vec::new()).iter().find(|e| {
            e.password == password
                && e.alg == opts.alg
                && e.key.len() == key_len
                && e.msec == 0
                && e.params == *params
        }) {
            entry.key.clone()
        } else {
            let k = pbkdf_manual(
                &opts.alg,
                botan_param_order,
                password,
                &salt,
                params.clone(),
                key_len,
                policy,
            )?;
            if let Some(c) = cache.as_mut() {
                c.push(PBKDFCacheEntry {
                    password: password.to_string(),
                    alg: opts.alg.clone(),
                    msec: 0,
                    salt: salt.clone(),
                    key: k.clone(),
                    params: params.clone(),
                });
            }
            k
        };
        return Ok((key, Some(format_phc(&opts.alg, params, &salt)?)));
    }

    let msec = opts
        .msec
        .ok_or_else(|| Error::Pbkdf("Missing PBKDF msec".into()))?;
    let (key, params) = if let Some(entry) =
        cache.as_ref().unwrap_or(&Vec::new()).iter().find(|e| {
            e.password == password && e.alg == opts.alg && e.key.len() == key_len && e.msec == msec
        }) {
        salt = entry.salt.clone();
        (entry.key.clone(), entry.params.clone())
    } else {
        let (k, p) = pbkdf_timed(
            &opts.alg,
            botan_param_order,
            password,
            &salt,
            msec,
            key_len,
            policy,
        )?;
        if let Some(c) = cache.as_mut() {
            c.push(PBKDFCacheEntry {
                password: password.to_string(),
                alg: opts.alg.clone(),
                msec,
                salt: salt.clone(),
                key: k.clone(),
                params: p.clone(),
            });
        }
        (k, p)
    };
    Ok((key, Some(format_phc(&opts.alg, &params, &salt)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phc_roundtrip_argon2() {
        let mut params = BTreeMap::new();
        params.insert("m".to_string(), 65536);
        params.insert("t".to_string(), 3);
        params.insert("p".to_string(), 4);
        let s = format_phc("argon2", &params, b"0123456789abcdef").unwrap();
        assert!(s.starts_with("$argon2$m=65536,p=4,t=3$"));
    }

    #[test]
    fn phc_roundtrip_pbkdf2() {
        let mut params = BTreeMap::new();
        params.insert("i".to_string(), 100_000);
        let s = format_phc("pbkdf2-sha512", &params, b"0123456789abcdef").unwrap();
        assert_eq!(s, "$pbkdf2-sha512$i=100000$MDEyMzQ1Njc4OWFiY2RlZg==");
    }

    #[test]
    fn phc_parse_accepts_padded_salt() {
        // Existing enprot blobs use base64 with `=` padding; the parser must
        // accept it.
        let (alg, params, salt) = parse_phc("$pbkdf2-sha256$i=1$AQIDBAUGBwg=").unwrap();
        assert_eq!(alg, "pbkdf2-sha256");
        assert_eq!(params.get("i").copied(), Some(1));
        assert_eq!(salt, b"\x01\x02\x03\x04\x05\x06\x07\x08");
    }

    #[test]
    fn phc_parse_rejects_missing_prefix() {
        assert!(parse_phc("pbkdf2-sha256$i=1$AQIDBAUGBwg=").is_err());
    }

    #[test]
    fn phc_parse_rejects_non_numeric_value() {
        assert!(parse_phc("$pbkdf2-sha256$i=abc$AQIDBAUGBwg=").is_err());
    }
}
