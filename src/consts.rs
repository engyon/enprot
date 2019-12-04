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

// pbkdf
pub const DEFAULT_PBKDF_ALG: &str = "argon2";
pub const DEFAULT_PBKDF_SALT_LEN: usize = 16;
pub const DEFAULT_PBKDF_MSEC: u32 = 100;
pub const DEFAULT_PBKDF2_HASH_ALG: &str = "sha256";

// cipher
pub const DEFAULT_CIPHER_ALG: &str = "aes-256-siv";
pub const VALID_CIPHER_ALGS: &[&str] = &["aes-256-siv", "aes-256-gcm"];
pub static BOTAN_CIPHER_ALG_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "aes-256-siv" => "AES-256/SIV",
    "aes-256-gcm" => "AES-256/GCM",
};

// parsing separators
pub const DEFAULT_LEFT_SEP: &str = "// <(";
pub const DEFAULT_RIGHT_SEP: &str = ")>";

// valid value lists
pub const VALID_PBKDF_ALGS: &[&str] = &["argon2", "scrypt", "pbkdf2", "legacy"];
pub const VALID_PBKDF2_HASH_ALGS: &[&str] = &["sha256", "sha512"];

// policies
pub const VALID_POLICIES: &[&str] = &["none"];
pub const DEFAULT_POLICY: &str = "none";
