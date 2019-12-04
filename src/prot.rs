// Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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

extern crate phc;
extern crate rpassword;

use std::collections::BTreeMap;

use crypto;
use crypto::CryptoPolicy;
use etree;
use pbkdf::derive_key;
use pbkdf::from_phc_alg;
use pbkdf::PBKDFCache;
use utils;

// Get a password

pub fn get_password(name: &str, rep: bool) -> String {
    let prompt = "Password for ".to_string() + name + ": ";
    let mut pass = rpassword::prompt_password_stdout(&prompt).unwrap();
    if rep {
        let prompt = "Repeat password for ".to_string() + name + ": ";
        let pass2 = rpassword::prompt_password_stdout(&prompt).unwrap();
        if pass != pass2 {
            eprintln!("Password mismatch. Try again.");
            pass = get_password(name, rep);
        }
    }
    pass
}

// Encrypt

pub fn encrypt(
    pt: Vec<u8>,
    password: &str,
    rng: &Option<botan::RandomNumberGenerator>,
    pbkdfopts: &etree::PBKDFOptions,
    cipheropts: &etree::CipherOptions,
    cache: &mut Option<PBKDFCache>,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<(Vec<u8>, BTreeMap<String, String>), &'static str> {
    let botan_cipher = crypto::to_botan_cipher(&cipheropts.alg)?;
    let key_len = crypto::cipher_key_len_min(botan_cipher)?;
    let (key, pbkdf) = derive_key(password, key_len, rng, pbkdfopts, cache, policy)?;
    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    if pbkdf != None {
        extfields.insert("pbkdf".to_string(), pbkdf.unwrap());
    }
    let mut iv: Vec<u8> = Vec::new();
    if !cipheropts.alg.ends_with("siv") {
        // IV required
        iv = if let Some(myiv) = cipheropts.iv.clone() {
            myiv
        } else {
            let ivlen = crypto::cipher_nonce_len(botan_cipher)?;
            rng.as_ref()
                .ok_or("Missing RNG")?
                .read(ivlen)
                .map_err(|_| "RNG error")?
        };
        extfields.insert(
            "cipher".to_string(),
            format!("{}$iv={}", &cipheropts.alg, utils::base64_encode(&iv)?).to_string(),
        );
    } else if cipheropts.iv != None {
        // IV not required
        return Err("IV was supplied but not expected");
    }
    Ok((
        crypto::encrypt(&botan_cipher, &key, &iv, &[], &pt, policy)?,
        extfields,
    ))
}

// Decrypt

pub fn decrypt(
    ct: Vec<u8>,
    password: &str,
    pbkdf: &Option<&String>,
    cipher: &Option<&String>,
    cache: &mut Option<PBKDFCache>,
    policy: &Box<dyn CryptoPolicy>,
) -> Result<Vec<u8>, &'static str> {
    let cipher_alg;
    let mut iv = Vec::new();
    if let Some(cipher) = cipher {
        let mut it = cipher.split("$");
        cipher_alg = it.next().ok_or("Invalid cipher extfield")?;
        let mut fields = BTreeMap::new();
        for val in it {
            let mut it = val.splitn(2, '=');
            let key = it.next().ok_or("Missing field key")?;
            let value = it.collect::<String>();
            fields.insert(key, value);
        }
        if let Some(myiv) = fields.get("iv") {
            iv = utils::base64_decode(myiv)?;
        }
    } else {
        cipher_alg = "aes-256-siv";
    }
    let botan_cipher = crypto::to_botan_cipher(&cipher_alg)?;
    let key_len = crypto::cipher_key_len_min(&botan_cipher)?;
    let key: Vec<u8>;
    if let Some(pbkdf) = pbkdf {
        let phc: phc::raw::RawPHC = pbkdf.parse().map_err(|_| "Failed to parse PHC")?;
        let (alg, pbkdf2_hash) = from_phc_alg(phc.id());
        let mut params_map: BTreeMap<String, usize> = BTreeMap::new();
        params_map.extend(
            phc.params()
                .iter()
                .map(|v| (v.0.to_string(), v.1.parse::<usize>().unwrap())),
        );
        let salt = match phc.salt().ok_or("Missing salt")? {
            phc::Salt::Ascii(s) => utils::base64_decode(s)?,
            phc::Salt::Binary(b) => utils::base64_decode(std::str::from_utf8(b).unwrap())?,
        };
        let pbkdfopts = etree::PBKDFOptions {
            alg: alg,
            saltlen: 0,
            salt: Some(salt),
            msec: None,
            pbkdf2_hash: pbkdf2_hash,
            params: Some(params_map),
        };
        let (thekey, _) = derive_key(password, key_len, &None, &pbkdfopts, cache, policy)?;
        key = thekey;
    } else {
        let (thekey, _) = derive_key(
            password,
            key_len,
            &None,
            &etree::PBKDFOptions {
                alg: "legacy".to_string(),
                saltlen: 0,
                salt: None,
                msec: None,
                pbkdf2_hash: None,
                params: None,
            },
            cache,
            policy,
        )?;
        key = thekey;
    }

    match crypto::decrypt(botan_cipher, &key, &iv, &[], &ct, policy) {
        Ok(pt) => Ok(pt),
        Err(_) => Err("Bad password?"),
    }
}
