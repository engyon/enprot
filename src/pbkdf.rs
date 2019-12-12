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

use phf::phf_map;
use std::collections::BTreeMap;

use crypto;
use crypto::CryptoPolicy;
use etree;
use utils;

pub static BOTAN_PBKDF_PARAM_MAP: phf::Map<&'static str, &[&[&str; 3]; 2]> = phf_map! {
    // alg      derive_key_from_password_timed()    derive_key_from_password()
    "argon2" => &[&["t", "p", "m"],                 &["m", "t", "p"]],
    "scrypt" => &[&["r", "p", "ln"],                &["ln", "r", "p"]],
    "pbkdf2-sha256" => &[&["i", "", ""],                   &["i", "", ""]],
    "pbkdf2-sha512" => &[&["i", "", ""],                   &["i", "", ""]],
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

fn pbkdf_legacy(
    password: &str,
    key_len: usize,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<Vec<u8>, &'static str> {
    policy.check_pbkdf("sha3-512", key_len, password, &[], &BTreeMap::new())?;
    let mut result = crypto::digest("sha3-512", password.as_bytes(), policy)?;
    result.truncate(key_len);
    Ok(result)
}

fn pbkdf_timed(
    alg: &str,
    botan_param_order: &[&[&str; 3]; 2],
    password: &str,
    salt: &Vec<u8>,
    msec: u32,
    key_len: usize,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<(Vec<u8>, BTreeMap<String, usize>), &'static str> {
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
    salt: &Vec<u8>,
    params_map: BTreeMap<String, usize>,
    key_len: usize,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<Vec<u8>, &'static str> {
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

fn format_phc(alg: &str, params: &BTreeMap<String, usize>, salt: &Vec<u8>) -> String {
    format!(
        "${}${}${}",
        alg,
        params
            .iter()
            .map(|v| format!("{}={}", v.0, v.1))
            .collect::<Vec<String>>()
            .join(","),
        utils::base64_encode(salt).unwrap()
    )
}

pub fn derive_key(
    password: &str,
    key_len: usize,
    rng: &Option<botan::RandomNumberGenerator>,
    opts: &etree::PBKDFOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<(Vec<u8>, Option<String>), &'static str> {
    if opts.alg == "legacy" {
        return Ok((pbkdf_legacy(password, key_len, policy)?, None));
    }
    let mut salt = opts.salt.clone().unwrap_or_else(|| {
        rng.as_ref()
            .unwrap()
            .read(opts.saltlen)
            .map_err(|_| "Failed to read from RNG")
            .unwrap()
    });
    let botan_param_order = BOTAN_PBKDF_PARAM_MAP
        .get::<str>(&opts.alg)
        .ok_or("Missing PBKDF param mapping")?;
    if let Some(params) = opts.params.as_ref() {
        let key;
        if let Some(entry) = cache.as_ref().unwrap_or(&Vec::new()).iter().find(|e| {
            e.password == password
                && e.alg == opts.alg
                && e.key.len() == key_len
                && e.msec == 0
                && e.params == *params
        }) {
            key = entry.key.clone();
        } else {
            key = pbkdf_manual(
                &opts.alg,
                &botan_param_order,
                password,
                &salt,
                opts.params.clone().unwrap(),
                key_len,
                policy,
            )?;
            if cache.is_some() {
                cache.as_mut().unwrap().push(PBKDFCacheEntry {
                    password: password.to_string(),
                    alg: opts.alg.clone(),
                    msec: 0,
                    salt: salt.clone(),
                    key: key.clone(),
                    params: params.clone(),
                });
            }
        }
        return Ok((
            key,
            Some(format_phc(&opts.alg, opts.params.as_ref().unwrap(), &salt)),
        ));
    }
    let (key, params);
    if let Some(entry) = cache.as_ref().unwrap_or(&Vec::new()).iter().find(|e| {
        e.password == password
            && e.alg == opts.alg
            && e.key.len() == key_len
            && e.msec == opts.msec.unwrap()
    }) {
        salt = entry.salt.clone();
        key = entry.key.clone();
        params = entry.params.clone();
    } else {
        let results = pbkdf_timed(
            &opts.alg,
            &botan_param_order,
            password,
            &salt,
            opts.msec.ok_or("Missing PBKDF msec")?,
            key_len,
            policy,
        )?;
        key = results.0;
        params = results.1;
        if cache.is_some() {
            cache.as_mut().unwrap().push(PBKDFCacheEntry {
                password: password.to_string(),
                alg: opts.alg.clone(),
                msec: opts.msec.unwrap(),
                salt: salt.clone(),
                key: key.clone(),
                params: params.clone(),
            });
        }
    }
    Ok((key, Some(format_phc(&opts.alg, &params, &salt))))
}
