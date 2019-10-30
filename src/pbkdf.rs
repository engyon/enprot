// Copyright (c) 2019 [Ribose Inc](https://www.ribose.com).
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

extern crate phf;

use self::phf::phf_map;
use std::collections::HashMap;

use consts;
use etree;
use utils;

pub static BOTAN_PBKDF_PARAM_MAP: phf::Map<&'static str, &[&[&str; 3]; 2]> = phf_map! {
    // alg      derive_key_from_password_timed()    derive_key_from_password()
    "argon2" => &[&["t", "p", "m"],                 &["m", "t", "p"]],
    "scrypt" => &[&["r", "p", "ln"],                &["ln", "r", "p"]],
    "pbkdf2" => &[&["i", "", ""],                   &["i", "", ""]],
};

static BOTAN_HASH_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "sha256" => "SHA-256",
    "sha512" => "SHA-512",
};

fn botan_pbkdf_name(alg: &str, pbkdf2_hash: &Option<String>) -> Result<String, &'static str> {
    match alg {
        "argon2" => Ok("Argon2id".to_string()),
        "scrypt" => Ok("Scrypt".to_string()),
        "pbkdf2" => {
            let hash = pbkdf2_hash
                .as_ref()
                .ok_or("Missing PBKDF2 hash algorithm")?;
            if let Some(hash) = BOTAN_HASH_ALG_MAP.get::<str>(&hash) {
                Ok(format!("PBKDF2({})", hash))
            } else {
                eprintln!("Invalid hash algorithm: '{}'", hash);
                Err("Invalid hash algorithm")
            }
        }
        _ => {
            eprintln!("Invalid KDF: '{}'", alg);
            Err("Invalid KDF")
        }
    }
}

fn pbkdf_legacy(password: &str) -> Vec<u8> {
    utils::digest("SHA-3(512)", password.as_bytes()).unwrap()
}

fn pbkdf_timed(
    botan_alg: &str,
    botan_param_order: &[&[&str; 3]; 2],
    password: &str,
    salt: &Vec<u8>,
    msec: u32,
) -> Result<(Vec<u8>, HashMap<String, usize>), &'static str> {
    let (key, param1, param2, param3) = botan::derive_key_from_password_timed(
        botan_alg,
        consts::AES256_KEY_LENGTH,
        password,
        &salt,
        msec,
    )
    .map_err(|_| "Botan error")?;
    let params = [param1, param2, param3];
    let mut params_map = HashMap::new();
    for (i, param) in botan_param_order[0]
        .iter()
        .filter(|v| !v.is_empty())
        .enumerate()
    {
        params_map.insert(param.to_string(), params[i]);
    }
    Ok((key, params_map))
}

fn pbkdf_manual(
    botan_alg: &str,
    botan_param_order: &[&[&str; 3]; 2],
    password: &str,
    salt: &Vec<u8>,
    mut params_map: HashMap<String, usize>,
) -> Result<Vec<u8>, &'static str> {
    let mut params: [usize; 3] = [0, 0, 0];
    for (i, param) in botan_param_order[1].iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        params[i] = params_map.remove(*param).ok_or("Missing PBKDF parameter")?;
    }
    if !params_map.is_empty() {
        return Err("Extraneous PBKDF parameters");
    }
    let key = botan::derive_key_from_password(
        botan_alg,
        consts::AES256_KEY_LENGTH,
        password,
        salt,
        params[0],
        params[1],
        params[2],
    )
    .map_err(|_| "Botan error")?;
    Ok(key)
}

fn to_phc_alg(alg: &str, pbkdf2_hash: &Option<String>) -> Result<String, &'static str> {
    match alg {
        "pbkdf2" => Ok(format!(
            "{}-{}",
            alg,
            pbkdf2_hash.as_ref().ok_or("Missing PBKDF2 hash")?
        )),
        _ => Ok(alg.to_string()),
    }
}

pub fn from_phc_alg(alg: &str) -> (String, Option<String>) {
    if alg.starts_with("pbkdf2-") {
        let parts = alg.splitn(2, "-").collect::<Vec<&str>>();
        return (parts[0].to_string(), Some(parts[1].to_string()));
    }
    return (alg.to_string(), None);
}

fn format_phc(alg: &str, params: &HashMap<String, usize>, salt: &Vec<u8>) -> String {
    let mut params: Vec<_> = params.iter().collect();
    params.sort_by(|a, b| a.0.cmp(b.0));
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
    rng: &Option<botan::RandomNumberGenerator>,
    opts: &etree::PBKDFOptions,
) -> Result<(Vec<u8>, Option<String>), &'static str> {
    if opts.alg == "legacy" {
        return Ok((pbkdf_legacy(password), None));
    }
    let botan_alg = botan_pbkdf_name(&opts.alg, &opts.pbkdf2_hash)?;
    let salt = opts.salt.clone().unwrap_or_else(|| {
        rng.as_ref()
            .unwrap()
            .read(opts.saltlen)
            .map_err(|_| "Failed to read from RNG")
            .unwrap()
    });
    let botan_param_order = BOTAN_PBKDF_PARAM_MAP
        .get::<str>(&opts.alg)
        .ok_or("Missing PBKDF param mapping")?;
    if opts.params != None {
        return Ok((
            pbkdf_manual(
                &botan_alg,
                &botan_param_order,
                password,
                &salt,
                opts.params.clone().unwrap(),
            )?,
            Some(format_phc(
                &to_phc_alg(&opts.alg, &opts.pbkdf2_hash)?,
                opts.params.as_ref().unwrap(),
                &salt,
            )),
        ));
    }
    let (key, params) = pbkdf_timed(
        &botan_alg,
        &botan_param_order,
        password,
        &salt,
        opts.msec.ok_or("Missing PBKDF msec")?,
    )?;
    Ok((
        key,
        Some(format_phc(
            &to_phc_alg(&opts.alg, &opts.pbkdf2_hash)?,
            &params,
            &salt,
        )),
    ))
}
