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

use std::collections::HashMap;

use consts;
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
    opts: &etree::PBKDFOptions,
    cache: &mut Option<PBKDFCache>,
) -> Result<(Vec<u8>, Option<String>), &'static str> {
    let (key, pbkdf) = derive_key(password, consts::AES256_KEY_LENGTH, rng, opts, cache)?;
    let enc = botan::Cipher::new("AES-256/SIV", botan::CipherDirection::Encrypt)
        .map_err(|_| "Botan error")?;
    enc.set_key(&key).map_err(|_| "Botan error")?;
    enc.set_associated_data(&[]).map_err(|_| "Botan error")?;
    Ok((enc.process(&[], &pt).map_err(|_| "Botan error")?, pbkdf))
}

// Decrypt

pub fn decrypt(
    ct: Vec<u8>,
    password: &str,
    pbkdf: &Option<String>,
    cache: &mut Option<PBKDFCache>,
) -> Result<Vec<u8>, &'static str> {
    let key: Vec<u8>;
    if let Some(pbkdf) = pbkdf {
        let phc: phc::raw::RawPHC = pbkdf.parse().map_err(|_| "Failed to parse PHC")?;
        let (alg, pbkdf2_hash) = from_phc_alg(phc.id());
        let mut params_map: HashMap<String, usize> = HashMap::new();
        params_map.extend(
            phc.params()
                .iter()
                .map(|v| (v.0.to_string(), v.1.parse::<usize>().unwrap())),
        );
        let salt = match phc.salt().ok_or("Missing salt")? {
            phc::Salt::Ascii(s) => utils::base64_decode(s)?,
            phc::Salt::Binary(b) => utils::base64_decode(std::str::from_utf8(b).unwrap())?,
        };
        let opts = etree::PBKDFOptions {
            alg: alg,
            saltlen: 0,
            salt: Some(salt),
            msec: None,
            pbkdf2_hash: pbkdf2_hash,
            params: Some(params_map),
        };
        let (thekey, _) = derive_key(password, consts::AES256_KEY_LENGTH, &None, &opts, cache)?;
        key = thekey;
    } else {
        let (thekey, _) = derive_key(
            password,
            consts::AES256_KEY_LENGTH,
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
        )?;
        key = thekey;
    }

    let dec = botan::Cipher::new("AES-256/SIV", botan::CipherDirection::Decrypt)
        .map_err(|_| "Botan error")?;
    dec.set_key(&key).map_err(|_| "Botan error")?;
    dec.set_associated_data(&[]).map_err(|_| "Botan error")?;
    match dec.process(&[], &ct) {
        Ok(pt) => Ok(pt),
        Err(_) => Err("Bad password?"),
    }
}
