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

//! Hardware-backed signature backend (TODO.complete/56) — abstraction
//! so chain anchor signing can move off the in-process PEM private key
//! path to PKCS#11 HSMs, TPM 2.0, or a macOS Secure Enclave without
//! changing call sites.
//!
//! ## v1 surface
//!
//! Only the `Software` backend is implemented (current behavior:
//! load the private key from a PEM file, sign in-process). The
//! `Signer` trait + `SignerBackend` enum give the rest of the
//! codebase a backend-agnostic surface; future backends land behind
//! feature flags (`hsm-pkcs11`, `hsm-tpm`, `hsm-enclave`) with
//! their own CI legs and their own runtime tests (real hardware or
//! the platform's simulation layer).
//!
//! The `signer-backend` CLI flag is a no-op for now: the only
//! variant is `software`. It exists so downstream code can be
//! written against the enum, and CI can assert the flag round-trips
//! without erroring.

use crate::error::Result;
use crate::pki::{self, SigAlgKind};
use botan::RandomNumberGenerator;

/// Which signature backend a [`Signer`] uses. v1: only
/// [`SignerBackend::Software`]. Future variants gated behind
/// features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignerBackend {
    /// In-process: load the private key from a PEM string and
    /// sign via `pki::sign`. The current behavior, and the
    /// default.
    #[default]
    Software,
}

/// A backend that produces a signature for `msg` under the
/// algorithm identified by `kind`.
///
/// The trait does not own the key material: each backend loads it
/// from whatever source the backend's constructor says (a PEM
/// string for `Software`, a slot/token for PKCS#11, a handle for
/// TPM, a key tag for the Secure Enclave). Callers do not see the
/// private key.
pub trait Signer: Send + Sync {
    /// Backend name, for error messages and audit logs.
    fn backend_name(&self) -> &'static str;

    /// Sign `msg` with the key this signer was constructed with.
    fn sign(
        &self,
        kind: SigAlgKind,
        msg: &[u8],
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>>;
}

/// Build a [`Signer`] for the requested backend. v1: every backend
/// delegates to [`SoftwareSigner`] (the only impl).
pub fn build_signer(backend: SignerBackend, privkey_pem: &str) -> Result<Box<dyn Signer>> {
    match backend {
        SignerBackend::Software => Ok(Box::new(SoftwareSigner::new(privkey_pem))),
    }
}

/// The current production signer: load the key from a PEM string,
/// sign via [`pki::sign`]. `pki::sign` already handles the
/// composite-algorithm split-into-legs dance, so this impl is a
/// thin adapter.
pub struct SoftwareSigner {
    privkey_pem: String,
}

impl SoftwareSigner {
    pub fn new(privkey_pem: &str) -> Self {
        Self {
            privkey_pem: privkey_pem.to_string(),
        }
    }
}

impl Signer for SoftwareSigner {
    fn backend_name(&self) -> &'static str {
        "software"
    }

    fn sign(
        &self,
        kind: SigAlgKind,
        msg: &[u8],
        rng: &mut RandomNumberGenerator,
    ) -> Result<Vec<u8>> {
        pki::sign(kind, &self.privkey_pem, msg, rng)
    }
}

/// Build a signer for the default backend ([`SignerBackend::Software`])
/// — the path the rest of the code takes today, unchanged.
pub fn default_signer(privkey_pem: &str) -> Result<Box<dyn Signer>> {
    build_signer(SignerBackend::default(), privkey_pem)
}

/// Lookup the backend by name. Accepts the kebab-case and
/// snake_case forms so the CLI flag (`software`) and the enum's
/// `value(rename_all = "kebab-case")` agree.
impl SignerBackend {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "software" | "SoftwareSigner" | "default" => Some(SignerBackend::Software),
            _ => None,
        }
    }
}

/// The v1 closed set of supported backend names, for diagnostics
/// and the CLI's `--help` text.
pub const SUPPORTED_BACKENDS: &[SignerBackend] = &[SignerBackend::Software];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki;

    fn rng() -> botan::RandomNumberGenerator {
        botan::RandomNumberGenerator::new_system().unwrap()
    }

    #[test]
    fn software_signer_round_trip() {
        let (priv_pem, _pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng()).unwrap();
        let signer = SoftwareSigner::new(&priv_pem);
        let msg = b"hello hardware-backed signer";
        let sig = signer.sign(SigAlgKind::Ed25519, msg, &mut rng()).unwrap();
        assert!(pki::verify(SigAlgKind::Ed25519, &_pub_pem, msg, &sig).unwrap());
    }

    #[test]
    fn build_signer_dispatches_to_software() {
        let (priv_pem, _) = pki::keygen(SigAlgKind::Ed25519, &mut rng()).unwrap();
        let signer = build_signer(SignerBackend::Software, &priv_pem).unwrap();
        assert_eq!(signer.backend_name(), "software");
    }

    #[test]
    fn default_signer_is_software() {
        assert_eq!(SignerBackend::default(), SignerBackend::Software);
    }

    #[test]
    fn parse_accepts_kebab_case_only() {
        assert_eq!(
            SignerBackend::parse("software"),
            Some(SignerBackend::Software)
        );
        assert!(SignerBackend::parse("pkcs11").is_none());
    }
}
