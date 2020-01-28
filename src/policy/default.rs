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

use std::collections::BTreeMap;

use policy::CryptoPolicy;

pub struct CryptoPolicyDefault {}

impl CryptoPolicyDefault {
    const DEFAULT_PBKDF_ALG: &'static str = "argon2";
    const DEFAULT_PBKDF_SALT_LEN: usize = 16;
    pub const DEFAULT_PBKDF_MSEC: u32 = 100;
    const DEFAULT_CIPHER_ALG: &'static str = "aes-256-siv";
}

// allow everything
impl CryptoPolicy for CryptoPolicyDefault {
    fn check_hash(&self, _alg: &str) -> Result<(), &'static str> {
        Ok(())
    }

    fn check_pbkdf(
        &self,
        _alg: &str,
        _key_len: usize,
        _password: &str,
        _salt: &[u8],
        _params: &BTreeMap<String, usize>,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn check_cipher(
        &self,
        _alg: &str,
        _key: &[u8],
        _iv: &[u8],
        _ad: &[u8],
    ) -> Result<(), &'static str> {
        Ok(())
    }

    fn default_pbkdf_alg(&self) -> String {
        Self::DEFAULT_PBKDF_ALG.to_string()
    }

    fn default_pbkdf_salt_length(&self) -> usize {
        Self::DEFAULT_PBKDF_SALT_LEN
    }

    fn default_pbkdf_millis(&self) -> u32 {
        Self::DEFAULT_PBKDF_MSEC
    }

    fn default_cipher_alg(&self) -> String {
        Self::DEFAULT_CIPHER_ALG.to_string()
    }
}
