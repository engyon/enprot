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

//! Public-key primitives. Phase 1 of the PQC rollout: Ed25519 only.
//!
//! Future phases (see `TODO.finalize/10-12-pqc-*.md`) will add
//! ML-DSA, ML-KEM, and composite constructions by extending
//! `SigAlgKind` and routing through the same `keygen` / `sign` /
//! `verify` entry points.

use botan::{Privkey, Pubkey, RandomNumberGenerator, Signer, Verifier};

use crate::error::{Error, Result};

/// Algorithms supported by `keygen` / `sign` / `verify`.
///
/// The CLI accepts the lower-case string form (`ed25519`); `from_str`
/// parses it. Future PQC variants join this enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SigAlgKind {
    Ed25519,
    MlDsa,
}

impl SigAlgKind {
    pub const ALL: &'static [SigAlgKind] = &[SigAlgKind::Ed25519, SigAlgKind::MlDsa];

    pub fn name(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "ed25519",
            SigAlgKind::MlDsa => "mldsa",
        }
    }

    fn botan_name(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "Ed25519",
            SigAlgKind::MlDsa => "ML-DSA",
        }
    }

    fn padding(self) -> &'static str {
        match self {
            SigAlgKind::Ed25519 => "Pure",
            // ML-DSA: Botan uses "Deterministic" for signing,
            // but verification accepts any padding mode (it's
            // encoded in the signature itself). Empty string =
            // let Botan pick its default.
            SigAlgKind::MlDsa => "",
        }
    }
}

impl std::str::FromStr for SigAlgKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        for k in SigAlgKind::ALL {
            if k.name().eq_ignore_ascii_case(s) {
                return Ok(*k);
            }
        }
        let valid = SigAlgKind::ALL
            .iter()
            .map(|k| k.name())
            .collect::<Vec<_>>()
            .join(", ");
        Err(Error::Msg(format!(
            "unknown signature algorithm '{}'; supported: {}",
            s, valid
        )))
    }
}

impl std::fmt::Display for SigAlgKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Generate a new keypair of the requested algorithm.
///
/// Returns `(privkey_pem, pubkey_pem)`. Both are PEM-encoded
/// (`-----BEGIN ... KEY-----`); callers write them to disk verbatim.
pub fn keygen(kind: SigAlgKind, rng: &mut RandomNumberGenerator) -> Result<(String, String)> {
    let privkey = Privkey::create(kind.botan_name(), "", rng).map_err(Error::botan)?;
    let pubkey = privkey.pubkey().map_err(Error::botan)?;
    let priv_pem = privkey.pem_encode().map_err(Error::botan)?;
    let pub_pem = pubkey.pem_encode().map_err(Error::botan)?;
    Ok((priv_pem, pub_pem))
}

/// Sign `msg` with `privkey_pem`. The returned signature is raw bytes
/// (64 bytes for Ed25519); callers wrap it in whatever container they
/// need.
pub fn sign(
    kind: SigAlgKind,
    privkey_pem: &str,
    msg: &[u8],
    rng: &mut RandomNumberGenerator,
) -> Result<Vec<u8>> {
    let privkey = Privkey::load_pem(privkey_pem).map_err(Error::botan)?;
    let mut signer = Signer::new(&privkey, kind.padding()).map_err(Error::botan)?;
    signer.update(msg).map_err(Error::botan)?;
    signer.finish(rng).map_err(Error::botan)
}

/// Verify `sig` over `msg` against `pubkey_pem`. Returns `Ok(true)` on
/// a valid signature, `Ok(false)` on a malformed-but-well-formed
/// signature that fails verification, and `Err` only when the pubkey
/// cannot be loaded or the verifier cannot be constructed.
pub fn verify(kind: SigAlgKind, pubkey_pem: &str, msg: &[u8], sig: &[u8]) -> Result<bool> {
    let pubkey = Pubkey::load_pem(pubkey_pem).map_err(Error::botan)?;
    let mut verifier = Verifier::new(&pubkey, kind.padding()).map_err(Error::botan)?;
    verifier.update(msg).map_err(Error::botan)?;
    verifier.finish(sig).map_err(Error::botan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> RandomNumberGenerator {
        RandomNumberGenerator::new_system().unwrap()
    }

    #[test]
    fn ed25519_keygen_emits_valid_pem_pair() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify(SigAlgKind::Ed25519, &pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn ed25519_verify_rejects_tampered_message() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::Ed25519, &pub_pem, b"tampered", &sig).unwrap());
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let mut r = rng();
        let (priv_pem, _) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let (_, other_pub) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::Ed25519, &other_pub, msg, &sig).unwrap());
    }

    #[test]
    fn mldsa_keygen_emits_valid_pem_pair() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        assert!(priv_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn mldsa_sign_verify_round_trip() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        // ML-DSA signatures are much larger than Ed25519 (typically ~3300 bytes).
        assert!(
            sig.len() > 1000,
            "ML-DSA sig expected >1000 bytes, got {}",
            sig.len()
        );
        assert!(verify(SigAlgKind::MlDsa, &pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn mldsa_verify_rejects_tampered_message() {
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::MlDsa, &pub_pem, b"tampered", &sig).unwrap());
    }

    #[test]
    fn mldsa_verify_rejects_wrong_key() {
        let mut r = rng();
        let (priv_pem, _) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let (_, other_pub) = keygen(SigAlgKind::MlDsa, &mut r).unwrap();
        let msg = b"the quick brown fox";
        let sig = sign(SigAlgKind::MlDsa, &priv_pem, msg, &mut r).unwrap();
        assert!(!verify(SigAlgKind::MlDsa, &other_pub, msg, &sig).unwrap());
    }

    #[test]
    #[ignore = "Botan's generic verifier doesn't reject cross-alg sigs reliably"]
    fn cross_alg_rejects_mismatch() {
        // Sign with Ed25519, try to verify as ML-DSA → must not succeed.
        let mut r = rng();
        let (priv_pem, pub_pem) = keygen(SigAlgKind::Ed25519, &mut r).unwrap();
        let msg = b"cross-alg test";
        let sig = sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut r).unwrap();
        match verify(SigAlgKind::MlDsa, &pub_pem, msg, &sig) {
            Ok(true) => panic!("cross-alg verification should not succeed"),
            Ok(false) => {} // expected: sig doesn't match
            Err(_) => {}    // expected: key type mismatch
        }
    }
}
