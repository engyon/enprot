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

/// Errors raised by enprot's library code. Every public function returns
/// `Result<T>` (= `std::result::Result<T, Error>`).
///
/// Variants are grouped by subsystem so callers can react to broad
/// categories (e.g. all policy violations, all PHC parse failures) without
/// matching every stringly-typed message.
#[derive(Debug, Error)]
pub enum Error {
    /// IO failure reading an input file, writing output, or reading CAS.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Botan FFI call returned an error. The payload is `botan::Error`'s
    /// `Display` form.
    #[error("botan: {0}")]
    Botan(String),

    /// `hex::decode` failed.
    #[error("hex: {0}")]
    Hex(String),

    /// `botan::base64_decode` failed.
    #[error("base64: {0}")]
    Base64(String),

    /// Cipher creation or processing failure (unknown algorithm, wrong key
    /// length, authentication failure on decrypt, etc.).
    #[error("cipher: {0}")]
    Cipher(String),

    /// PBKDF parameter resolution or key derivation failure.
    #[error("pbkdf: {0}")]
    Pbkdf(String),

    /// `CryptoPolicy` rejected the requested algorithm or parameters.
    #[error("policy violation: {0}")]
    Policy(String),

    /// EPT markup parse failure. `file` is the source path or `<stdin>`;
    /// `lineno` is 1-based, 0 when the error isn't line-bound.
    #[error("parse error in {file}:{lineno}: {msg}")]
    Parse {
        file: String,
        lineno: i32,
        msg: String,
    },

    /// CAS load/save failure (hash mismatch, missing file, etc.).
    #[error("CAS: {0}")]
    Cas(String),

    /// PHC string parse failure (missing `$`, non-numeric param value,
    /// bad base64 salt, etc.).
    #[error("PHC: {0}")]
    Phc(String),

    /// JSON serialization failure (output DTO could not be rendered).
    #[error("JSON: {0}")]
    Json(String),

    /// Catch-all for one-off messages that don't fit a more specific
    /// variant. Prefer adding a new variant when the same message shape
    /// appears in more than one place.
    #[error("{0}")]
    Msg(String),
}

impl Error {
    /// Wrap any `Display` value (typically `botan::Error`) as `Error::Botan`.
    pub fn botan(e: impl std::fmt::Display) -> Self {
        Error::Botan(e.to_string())
    }

    /// Construct `Error::Msg` from anything stringifiable.
    pub fn msg(s: impl Into<String>) -> Self {
        Error::Msg(s.into())
    }

    /// Construct `Error::Json` from anything stringifiable.
    pub fn json(e: impl std::fmt::Display) -> Self {
        Error::Json(e.to_string())
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

/// Convenience alias used everywhere in the crate.
pub type Result<T> = std::result::Result<T, Error>;
