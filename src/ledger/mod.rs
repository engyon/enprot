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

//! Chain anchor DAG (Stage 1, TODO.finalize/17).
//!
//! A chain anchor attests: "the file looked like this at this point,
//! signed by me, building on these previous anchors." Anchors form a
//! DAG, not a linear chain — multiple writers can fork and merge
//! without locks.
//!
//! This module owns the typed [`Anchor`] model plus the signing and
//! verification logic. Parser and CLI integration land in follow-up
//! PRs; this module is self-contained and fully testable in isolation.
//!
//! See `docs/src/pages/docs/chain-dag.astro` for the design rationale
//! and `TODO.finalize/17-chain-dag.md` for the full scope.

pub mod anchor;
pub mod dag;

pub use anchor::{Anchor, AnchorBuilder, SignedAnchor};
pub use dag::{AnchorDag, DagError, DagReport};

use crate::error::Result;

/// Sign a freshly-built anchor with the caller's private key. The
/// signer fingerprint is taken from the corresponding pubkey (caller
/// supplies both — they're typically loaded from the same PEM pair).
///
/// Returns a [`SignedAnchor`] carrying the signature. The `Anchor`
/// itself is unchanged; signing is non-destructive so the same anchor
/// can be signed by multiple parties (multi-sig contract mode, TODO 28).
pub fn sign_anchor(
    anchor: &Anchor,
    privkey_pem: &str,
    pubkey_pem: &str,
    alg: crate::pki::SigAlgKind,
) -> Result<SignedAnchor> {
    anchor.sign(privkey_pem, pubkey_pem, alg)
}

/// Verify a signed anchor's signature against the embedded signer
/// fingerprint. Returns `Ok(())` if the signature is valid, `Err` if
/// not or if the pubkey doesn't match the recorded fingerprint.
pub fn verify_anchor(signed: &SignedAnchor, pubkey_pem: &str) -> Result<()> {
    signed.verify(pubkey_pem)
}
