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

//! Signer provider abstraction (TODO.roadmap/10).
//!
//! [`SignerProvider`] abstracts how signatures are produced. Today,
//! [`PemSigner`] wraps the existing PEM-based path. Future
//! implementations:
//!
//! - [`ConfiumSigner`](TODO.roadmap/20) — threshold signing via FROST
//! - `Pkcs11Signer` — hardware token signing
//!
//! All implementations return the same shape: algorithm, raw signature
//! bytes, and the key fingerprint. The wire format is identical —
//! verifiers can't tell whether threshold was used.

use std::path::Path;

use crate::capability::KeyFp;
use crate::error::{Error, Result};
use crate::pki::{self, SigAlgKind};

/// How signatures are produced. The trait abstracts over single-party
/// PEM keys, threshold (Confium), hardware (PKCS#11), and any future
/// signing backend.
///
/// Callers receive `(algorithm, signature_bytes, fingerprint)` and
/// embed them in the chain anchor wire format. The fingerprint is the
/// group key's fingerprint for threshold, or the individual key's for
/// single-party.
pub trait SignerProvider: Send + Sync + std::fmt::Debug {
    /// Sign a message. Returns algorithm, raw signature, key fingerprint.
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;

    /// The key fingerprint this provider signs under.
    fn fingerprint(&self) -> Result<KeyFp>;
}

/// Single-party PEM-backed signer. Wraps today's `pki::sign` path.
/// This is the default `SignerProvider` — what you get with
/// `--signer priv.pem`.
#[derive(Debug)]
pub struct PemSigner {
    priv_pem: String,
    alg: SigAlgKind,
    fp: KeyFp,
}

impl PemSigner {
    /// Load a PEM private key and derive its pubkey fingerprint.
    /// Algorithm defaults to Ed25519 unless specified.
    pub fn from_file(priv_path: &Path, alg: SigAlgKind) -> Result<Self> {
        let priv_pem = std::fs::read_to_string(priv_path)?;
        Self::from_pem(&priv_pem, alg)
    }

    /// Construct from an in-memory PEM string. Derives the pubkey
    /// via Botan's `Privkey::pubkey()` and computes the fingerprint.
    pub fn from_pem(priv_pem: &str, alg: SigAlgKind) -> Result<Self> {
        let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
        let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
        let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
        let fp = KeyFp::from_pem(&pub_pem)?;
        Ok(PemSigner {
            priv_pem: priv_pem.to_string(),
            alg,
            fp,
        })
    }

    /// The pubkey PEM (derived from the privkey at construction time).
    pub fn pub_pem(&self) -> Result<String> {
        let botan_priv = botan::Privkey::load_pem(&self.priv_pem).map_err(Error::botan)?;
        let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
        botan_pub.pem_encode().map_err(Error::botan)
    }
}

impl SignerProvider for PemSigner {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
        let sig = pki::sign(self.alg, &self.priv_pem, msg, &mut rng)?;
        Ok((self.alg, sig, self.fp))
    }

    fn fingerprint(&self) -> Result<KeyFp> {
        Ok(self.fp)
    }
}

/// Parse a `--signer` CLI argument into a boxed [`SignerProvider`].
///
/// Supported URI schemes:
/// - Bare path (`priv.pem`) → [`PemSigner`] with Ed25519
/// - `confium://...` → `ConfiumSigner` (TODO.roadmap/22 — not yet implemented)
/// - `pkcs11://...` → `Pkcs11Signer` (future)
pub fn parse_signer_arg(s: &str, alg: SigAlgKind) -> Result<Box<dyn SignerProvider>> {
    if s.starts_with("confium://") {
        Err(Error::msg(
            "Confium threshold signing not yet implemented (see TODO.roadmap/22)",
        ))
    } else if s.starts_with("pkcs11://") {
        Err(Error::msg("PKCS#11 hardware signing not yet implemented"))
    } else {
        let signer = PemSigner::from_file(Path::new(s), alg)?;
        Ok(Box::new(signer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_pem() -> String {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, _) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        priv_pem
    }

    #[test]
    fn pem_signer_round_trip() {
        let priv_pem = ed25519_pem();
        let signer = PemSigner::from_pem(&priv_pem, SigAlgKind::Ed25519).unwrap();
        let msg = b"test message";
        let (alg, sig, fp) = signer.sign(msg).unwrap();
        assert_eq!(alg, SigAlgKind::Ed25519);
        assert_eq!(sig.len(), 64);

        // Verify the signature
        let pub_pem = signer.pub_pem().unwrap();
        assert!(pki::verify(SigAlgKind::Ed25519, &pub_pem, msg, &sig).unwrap());

        // Fingerprint matches
        let expected_fp = KeyFp::from_pem(&pub_pem).unwrap();
        assert_eq!(fp, expected_fp);
        assert_eq!(signer.fingerprint().unwrap(), expected_fp);
    }

    #[test]
    fn parse_bare_path_returns_pem_signer() {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, _) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("priv.pem");
        std::fs::write(&path, &priv_pem).unwrap();

        let signer = parse_signer_arg(path.to_str().unwrap(), SigAlgKind::Ed25519);
        assert!(signer.is_ok());
    }

    #[test]
    fn parse_confium_uri_returns_not_yet_implemented() {
        let result = parse_signer_arg("confium://session-1", SigAlgKind::Ed25519);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not yet implemented"));
    }

    #[test]
    fn parse_pkcs11_uri_returns_not_yet_implemented() {
        let result = parse_signer_arg("pkcs11://token-1", SigAlgKind::Ed25519);
        assert!(result.is_err());
    }
}
