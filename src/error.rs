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

    /// Cipher algorithm not recognized by any backend.
    #[error("unknown cipher algorithm: {alg}")]
    CipherUnknown { alg: String },

    /// AEAD encrypt or decrypt operation failed (authentication tag
    /// mismatch, wrong key, corrupted ciphertext). The underlying
    /// AEAD error is opaque (no structured data), so we carry the
    /// algorithm name and operation for diagnostics.
    #[error("AEAD {op} failed for {alg}")]
    AeadFailed { alg: &'static str, op: &'static str },

    /// `CryptoPolicy` rejected the requested algorithm or parameters.
    #[error("policy violation: {0}")]
    Policy(String),

    /// Capability policy (`.enprot/policy.toml`, TODO.roadmap/46) rejected
    /// an operation. `rule` identifies which clause triggered; `context`
    /// carries the offending value (anchor ID, WORD name, fingerprint).
    #[error("capability policy '{rule}' violated: {context}")]
    PolicyViolation { rule: String, context: String },

    /// EPT markup parse failure. `file` is the source path or `<stdin>`;
    /// `lineno` is 1-based, 0 when the error isn't line-bound.
    #[error("parse error in {file}:{lineno}: {msg}")]
    Parse {
        file: String,
        lineno: i32,
        msg: String,
    },

    /// CAS load/save failure (hash mismatch, missing file, etc.).
    /// Prefer the structured variants below for new code; this remains
    /// for cases that don't fit a specific category.
    #[error("CAS: {0}")]
    Cas(String),

    /// CAS hash is not valid hex (wrong length or non-hex chars).
    #[error("CAS hash invalid: {hash}")]
    CasHashInvalid { hash: String },

    /// CAS blob content doesn't match its declared hash.
    #[error("CAS hash mismatch: expected {expected}, computed {actual}")]
    CasHashMismatch { expected: String, actual: String },

    /// CAS blob not found in the store.
    #[error("CAS blob not found: {hash}")]
    CasNotFound { hash: String },

    /// CAS operation not supported by the backend (e.g., `list()` on
    /// an append-only store).
    #[error("CAS operation '{op}' not supported by this backend")]
    CasUnsupported { op: &'static str },

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

    /// Invalid argument value supplied by the caller. `arg` is the
    /// flag/parameter name; `reason` is the human-readable validation
    /// failure. Distinguished from `Policy` (algorithm-gating) and
    /// `Msg` (generic) so the FFI can return `ENPROT_ERR_INVALID`.
    #[error("invalid argument {arg}: {reason}")]
    InvalidArg { arg: &'static str, reason: String },

    /// Wire-format extfield (`pbkdf:`, `cipher:`, `signer:`, etc.)
    /// failed to parse or validate. `field` is the extfield name
    /// (without the trailing `=`); `reason` is the parse failure.
    #[error("extfield {field} malformed: {reason}")]
    Extfield { field: &'static str, reason: String },

    /// Signature verification failed. `key_id` is the fingerprint or
    /// label that was being verified against. Carries no `source`
    /// because signature verify is a boolean result, not a nested
    /// error.
    #[error("signature verification failed for {key_id}")]
    SignatureVerify { key_id: String },

    /// EPT block shape error — the wrong kind of children inside a
    /// BeginEnd or Encrypted block. `word` is the affected WORD;
    /// `reason` describes what was expected vs found.
    #[error("block {word} shape error: {reason}")]
    BlockShape { word: String, reason: String },

    /// CONFLICT-block resolution failure. `word` is the WORD under
    /// conflict; `reason` is why resolution didn't succeed.
    #[error("conflict resolution failed for {word}: {reason}")]
    ConflictResolve { word: String, reason: String },
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

    /// Wrap this error with additional context (file path, WORD,
    /// operation name). Produces a richer Display string without
    /// changing the error type. Usage:
    ///
    /// ```ignore
    /// KeyFp::from_pem(&pem)
    ///     .map_err(|e| e.with_context(format!("loading {}", path.display())))?
    /// ```
    ///
    /// The Display output becomes:
    /// `"loading builder.pem: signer fingerprint mismatch"`
    pub fn with_context(self, ctx: impl std::fmt::Display) -> Self {
        Error::Msg(format!("{}: {}", ctx, self))
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

impl From<crate::ledger::DagError> for Error {
    fn from(e: crate::ledger::DagError) -> Self {
        Error::msg(e.to_string())
    }
}

/// Convenience alias used everywhere in the crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Display output is a stable contract for users who grep on
    /// error messages. These snapshots lock the format.
    #[test]
    fn display_invalid_arg() {
        let e = Error::InvalidArg {
            arg: "--word",
            reason: "missing".to_string(),
        };
        assert_eq!(e.to_string(), "invalid argument --word: missing");
    }

    #[test]
    fn display_extfield() {
        let e = Error::Extfield {
            field: "payload",
            reason: "CHAIN missing required 'payload' field".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "extfield payload malformed: CHAIN missing required 'payload' field"
        );
    }

    #[test]
    fn display_signature_verify() {
        let e = Error::SignatureVerify {
            key_id: "ed25519:abcd".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "signature verification failed for ed25519:abcd"
        );
    }

    #[test]
    fn display_block_shape() {
        let e = Error::BlockShape {
            word: "SECRET".to_string(),
            reason: "ENCRYPTED block has no DATA or STORED child".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "block SECRET shape error: ENCRYPTED block has no DATA or STORED child"
        );
    }

    #[test]
    fn display_conflict_resolve() {
        let e = Error::ConflictResolve {
            word: "AGENT".to_string(),
            reason: "no resolution strategy picked".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "conflict resolution failed for AGENT: no resolution strategy picked"
        );
    }

    #[test]
    fn display_io() {
        let e = Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(e.to_string().contains("i/o error"));
    }

    #[test]
    fn display_botan() {
        let e = Error::Botan("rng failure".to_string());
        assert_eq!(e.to_string(), "botan: rng failure");
    }

    #[test]
    fn display_hex() {
        let e = Error::Hex("odd-length".to_string());
        assert_eq!(e.to_string(), "hex: odd-length");
    }

    #[test]
    fn display_base64() {
        let e = Error::Base64("invalid char".to_string());
        assert_eq!(e.to_string(), "base64: invalid char");
    }

    #[test]
    fn display_policy() {
        let e = Error::Policy("sha1 not approved".to_string());
        assert_eq!(e.to_string(), "policy violation: sha1 not approved");
    }

    #[test]
    fn display_policy_violation() {
        let e = Error::PolicyViolation {
            rule: "trust_root".to_string(),
            context: "signer abc not in trust_roots".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "capability policy 'trust_root' violated: signer abc not in trust_roots"
        );
    }

    #[test]
    fn display_parse() {
        let e = Error::Parse {
            file: "test.ept".to_string(),
            lineno: 42,
            msg: "unexpected END".to_string(),
        };
        assert_eq!(e.to_string(), "parse error in test.ept:42: unexpected END");
    }

    #[test]
    fn display_cas() {
        let e = Error::Cas("hash mismatch".to_string());
        assert_eq!(e.to_string(), "CAS: hash mismatch");
    }

    #[test]
    fn display_phc() {
        let e = Error::Phc("missing $ separator".to_string());
        assert_eq!(e.to_string(), "PHC: missing $ separator");
    }

    #[test]
    fn display_json() {
        let e = Error::Json("unexpected EOF".to_string());
        assert_eq!(e.to_string(), "JSON: unexpected EOF");
    }

    #[test]
    fn display_msg() {
        let e = Error::Msg("something happened".to_string());
        assert_eq!(e.to_string(), "something happened");
    }

    #[test]
    fn display_cas_hash_invalid() {
        let e = Error::CasHashInvalid {
            hash: "xyz".to_string(),
        };
        assert_eq!(e.to_string(), "CAS hash invalid: xyz");
    }

    #[test]
    fn display_cas_hash_mismatch() {
        let e = Error::CasHashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "CAS hash mismatch: expected aaa, computed bbb"
        );
    }

    #[test]
    fn display_cas_not_found() {
        let e = Error::CasNotFound {
            hash: "abc123".to_string(),
        };
        assert_eq!(e.to_string(), "CAS blob not found: abc123");
    }

    #[test]
    fn display_cas_unsupported() {
        let e = Error::CasUnsupported { op: "list" };
        assert_eq!(
            e.to_string(),
            "CAS operation 'list' not supported by this backend"
        );
    }

    #[test]
    fn display_cipher_unknown() {
        let e = Error::CipherUnknown {
            alg: "aes-999".to_string(),
        };
        assert_eq!(e.to_string(), "unknown cipher algorithm: aes-999");
    }

    #[test]
    fn display_aead_failed() {
        let e = Error::AeadFailed {
            alg: "aes-256-gcm-siv",
            op: "decrypt",
        };
        assert_eq!(e.to_string(), "AEAD decrypt failed for aes-256-gcm-siv");
    }
}
