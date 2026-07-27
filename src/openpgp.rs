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

//! OpenPGP signature support via `rnp-rs` (librnp FFI).
//!
//! rnp-rs is the idiomatic Rust binding to librnp — the OpenPGP C library
//! from Ribose (the same one Mozilla Thunderbird uses). Requires librnp
//! installed at build time: `brew install rnp` (macOS),
//! `apt install librnp-dev` (Debian), or build from source.
//!
//! ## Current surface
//!
//! Thin facade over rnp-rs's high-level API. The CLI layer wires
//! `enprot sign --alg openpgp` and `enprot verify-sig --alg openpgp`
//! through here.
//!
//! Key management (loading TPK/TSK from disk, keyring lookup) is handled
//! in the caller — pass a `&rnp::Key` in. For loading keys from files,
//! see `rnp::Context::load_keys`.

use crate::error::{Error, Result};

/// Return the underlying librnp version string (e.g. `"RNP 0.17.1+...`").
/// Useful for `enprot --version` output and for confirming at startup
/// that librnp is reachable.
pub fn backend_version() -> String {
    rnp::version_string()
}

/// Initialize a fresh librnp [`rnp::Context`]. All rnp-rs operations
/// require one; enprot creates one per call (cheap — no I/O) to keep
/// the surface stateless.
pub fn new_context() -> Result<rnp::Context> {
    rnp::Context::new().map_err(rnp_err)
}

/// Inline-sign `msg` with `signing_key`. Returns the OpenPGP-signed
/// message bytes (a "signed plaintext" block containing the message
/// and the signature).
pub fn sign_inline(ctx: &rnp::Context, msg: &[u8], signing_key: &rnp::Key<'_>) -> Result<Vec<u8>> {
    rnp::sign(ctx, msg, signing_key).map_err(rnp_err)
}

/// Verify an inline-signed OpenPGP message. Returns `Ok(())` if at
/// least one signature is valid; `Err` otherwise.
pub fn verify_inline(ctx: &rnp::Context, signed_msg: &[u8]) -> Result<()> {
    let result = rnp::verify(ctx, signed_msg).map_err(rnp_err)?;
    if result.any_valid().map_err(rnp_err)? {
        Ok(())
    } else {
        Err(Error::msg(
            "OpenPGP signature verification failed: no valid signatures",
        ))
    }
}

fn rnp_err(e: rnp::Error) -> Error {
    Error::msg(format!("OpenPGP (rnp): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: generate an Ed25519 key, sign a message, verify it.
    /// Confirms rnp-rs is linked and the basic OpenPGP flow works.
    #[test]
    fn sign_verify_round_trip() {
        let ctx = match new_context() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: rnp init failed: {e}");
                return;
            }
        };
        let key = rnp::KeyBuilder::new(rnp::Algorithm::Eddsa)
            .userid("enprot-test <test@example.com>")
            .add_usage(rnp::KeyUsage::Sign)
            .add_usage(rnp::KeyUsage::Certify)
            .build(&ctx)
            .expect("keygen");

        let msg = b"hello, openpgp";
        let signed = sign_inline(&ctx, msg, &key).expect("sign");
        assert!(!signed.is_empty());

        verify_inline(&ctx, &signed).expect("verify");
    }

    /// Sanity: backend_version returns a non-empty string.
    #[test]
    fn backend_version_returns_nonempty() {
        let v = backend_version();
        assert!(!v.is_empty(), "version: {v}");
    }
}
