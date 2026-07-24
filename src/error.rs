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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("botan: {0}")]
    Botan(String),

    #[error("hex: {0}")]
    Hex(String),

    #[error("base64: {0}")]
    Base64(String),

    #[error("cipher: {0}")]
    Cipher(String),

    #[error("pbkdf: {0}")]
    Pbkdf(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("parse error in {file}:{lineno}: {msg}")]
    Parse {
        file: String,
        lineno: i32,
        msg: String,
    },

    #[error("CAS: {0}")]
    Cas(String),

    #[error("PHC: {0}")]
    Phc(String),

    #[error("{0}")]
    Msg(String),
}

impl Error {
    pub fn botan(e: impl std::fmt::Display) -> Self {
        Error::Botan(e.to_string())
    }

    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }
}

impl From<botan::Error> for Error {
    fn from(e: botan::Error) -> Self {
        Error::Botan(e.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Hex(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
