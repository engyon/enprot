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

extern crate crypto;
extern crate miscreant;
extern crate rpassword;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use self::miscreant::siv::Aes256Siv;

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

pub fn encrypt(pt: Vec<u8>, password: Vec<u8>) -> Vec<u8> {
    let no_ad = vec![vec![]];
    let mut sivkey = [0; 64];
    let mut khash = Sha3::sha3_512();
    khash.input(&password);
    khash.result(&mut sivkey);

    Aes256Siv::new(&sivkey).seal(&no_ad, &pt)
}

// Decrypt

pub fn decrypt(ct: Vec<u8>, password: Vec<u8>) -> Option<Vec<u8>> {
    let no_ad = vec![vec![]];
    let mut sivkey = [0; 64];
    let mut khash = Sha3::sha3_512();
    khash.input(&password);
    khash.result(&mut sivkey);

    // The miscreant error type is really uninformative (good!)
    match Aes256Siv::new(&sivkey).open(&no_ad, &ct) {
        Ok(pt) => Some(pt),
        Err(_) => None,
    }
}
