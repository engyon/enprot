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

extern crate botan;

pub fn digest(alg: &str, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let hash = botan::HashFunction::new(alg).map_err(|_| "Botan error")?;
    hash.update(data).map_err(|_| "Botan error")?;
    hash.finish().map_err(|_| "Botan error")
}

pub fn hexdigest(alg: &str, data: &[u8]) -> Result<String, &'static str> {
    Ok(hex::encode(digest(alg, data)?))
}

pub fn base64_encode(data: &[u8]) -> Result<String, &'static str> {
    botan::base64_encode(data).map_err(|_| "Botan error")
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>, &'static str> {
    botan::base64_decode(data).map_err(|_| "Botan error")
}