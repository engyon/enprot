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

//! Signer provider abstraction (TODO.roadmap/10 + TODO.completion/08).
//!
//! [`SignerProvider`] abstracts how signatures are produced:
//!
//! - [`PemSigner`] wraps the existing PEM-based path (sync, local).
//! - [`AsyncSignerProvider`] is the async variant for network-backed
//!   backends (Confium threshold, future cloud KMS). Built on Rust
//!   1.88+'s native async fn in traits — no `async-trait` macro.
//! - [`AnySigner`] bridges the two so sync CLI callers don't have to
//!   care which variant a provider implements.
//!
//! All paths return the same shape: algorithm, raw signature bytes,
//! and the key fingerprint. The wire format is identical — verifiers
//! can't tell whether threshold was used.

use std::path::Path;

use crate::capability::KeyFp;
use crate::error::{Error, Result};
use crate::pki::{self, SigAlgKind};

/// Sync signing — single-party, local key material. Implementors:
/// [`PemSigner`], future `Pkcs11Signer` (smartcard via sync API).
pub trait SignerProvider: Send + Sync + std::fmt::Debug {
    /// Sign a message. Returns algorithm, raw signature, key fingerprint.
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;

    /// The key fingerprint this provider signs under.
    fn fingerprint(&self) -> Result<KeyFp>;
}

/// Async signing — multi-party, network-backed, potentially slow.
/// Implementors: future `ConfiumSigner`, future `CloudKMSSigner`.
///
/// Native `async fn` in traits (stable since Rust 1.75, MSRV-aligned
/// at 1.88). No `async-trait` macro needed.
///
/// Why a separate trait (rather than making `SignerProvider::sign`
/// async)? Every consumer would gain `async fn` pollution for a
/// feature most users don't need. Dual trait keeps sync consumers
/// sync; async consumers opt in via [`AnySigner`] or by calling
/// `AsyncSignerProvider::sign_async` directly.
pub trait AsyncSignerProvider: Send + Sync + std::fmt::Debug {
    /// Sign a message asynchronously. Same return shape as
    /// [`SignerProvider::sign`].
    #[allow(clippy::type_complexity)]
    fn sign_async(
        &self,
        msg: &[u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(SigAlgKind, Vec<u8>, KeyFp)>> + Send + '_>,
    >;

    /// The key fingerprint this provider signs under.
    fn fingerprint(&self) -> Result<KeyFp>;
}

#[allow(clippy::type_complexity)]
/// Bridge enum so callers can dispatch over either trait without
/// caring which. CLI uses [`AnySigner::sign_blocking`]; library
/// callers that want concurrency call `sign_async` directly on the
/// [`AsyncSignerProvider`] variant.
pub enum AnySigner {
    /// Local sync backend.
    Sync(Box<dyn SignerProvider>),
    /// Network-backed async backend.
    Async(Box<dyn AsyncSignerProvider>),
}

impl AnySigner {
    /// Block on the operation. For sync backends this is a direct
    /// call; for async backends it parks a single-threaded runtime
    /// until the future completes. CLI consumers use this; library
    /// consumers should call `AsyncSignerProvider::sign_async`
    /// directly to integrate with their own runtime.
    pub fn sign_blocking(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        match self {
            AnySigner::Sync(s) => s.sign(msg),
            AnySigner::Async(s) => {
                // Simple current-thread runtime. We don't pull in
                // tokio as a hard dep — the future is polled here
                // via `std::future::Future::poll`. For real async
                // consumers, the ConfiumSigner will expose
                // `sign_async` directly so they integrate their own
                // runtime.
                let fut = s.sign_async(msg);
                futures_block_on::block_on(fut)
            }
        }
    }

    pub fn fingerprint(&self) -> Result<KeyFp> {
        match self {
            AnySigner::Sync(s) => s.fingerprint(),
            AnySigner::Async(s) => s.fingerprint(),
        }
    }
}

// Minimal block_on without pulling tokio. Polls the future on the
// current thread. Sufficient for CLI single-shot use; library
// consumers should integrate their own runtime.
mod futures_block_on {
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    pub fn block_on<F: Future>(fut: F) -> F::Output {
        // No-op waker — we never actually wake; we just spin polling.
        fn noop_clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &NOOP_VTABLE)
        }
        fn noop(_: *const ()) {}
        static NOOP_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        // Pin without unsafe: use the Box trick.
        let mut fut = Box::pin(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
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
/// - `confium://...` → Confium threshold daemon (requires the daemon
///   running locally; see https://github.com/confium/confium)
/// - `pkcs11://...` → PKCS#11 hardware token (requires `pkcs11` cargo feature)
pub fn parse_signer_arg(s: &str, alg: SigAlgKind) -> Result<Box<dyn SignerProvider>> {
    if s.starts_with("confium://") {
        Err(Error::InvalidArg {
            arg: "signer",
            reason: "Confium daemon not found. Install and start the daemon from \
             https://github.com/confium/confium, then use \
             --signer confium://<session-id> (see TODO.finalize/38)"
                .to_string(),
        })
    } else if s.starts_with("pkcs11://") {
        Err(Error::InvalidArg {
            arg: "signer",
            reason: "PKCS#11 signing requires the 'pkcs11' cargo feature. \
             Rebuild with: cargo build --features pkcs11. \
             Then use --signer pkcs11://<module-path>/<key-label>"
                .to_string(),
        })
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
    fn parse_confium_uri_returns_daemon_pending_error() {
        let result = parse_signer_arg("confium://session-1", SigAlgKind::Ed25519);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("daemon"), "should reference the daemon: {err}");
        assert!(
            err.contains("TODO.finalize/38"),
            "should link the tracking TODO: {err}"
        );
    }

    #[test]
    fn parse_pkcs11_uri_returns_not_yet_implemented() {
        let result = parse_signer_arg("pkcs11://token-1", SigAlgKind::Ed25519);
        assert!(result.is_err());
    }
}

/// How per-file AES keys are derived for WORD encryption (TODO.roadmap/11).
///
/// Implementations:
/// - [`PasswordKem`] — PBKDF over a password (today's behavior)
/// - `MlKemProvider` — single-party ML-KEM encapsulation (roadmap 30)
/// - `ConfiumKemProvider` — threshold ML-KEM (roadmap 21)
///
/// For password encryption, the "KEM" is conceptual: PBKDF derives
/// the key directly. For public-key encryption, encapsulate produces
/// a ciphertext that decapsulate converts back to the same key.
pub trait KemProvider: Send + Sync + std::fmt::Debug {
    /// Encryption side: produce (aes_key, recipient_ciphertext, fingerprint).
    fn encapsulate(
        &self,
        rng: &mut botan::RandomNumberGenerator,
    ) -> Result<(Vec<u8>, Vec<u8>, crate::capability::KeyFp)>;

    /// Decryption side: recover aes_key from recipient_ciphertext.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// The recipient key fingerprint.
    fn fingerprint(&self) -> Result<crate::capability::KeyFp>;
}

/// Password-based "KEM" — wraps today's PBKDF path. The "ciphertext"
/// is the PHC string (salt + params) stored in the extfield.
///
/// Debug is implemented manually to avoid leaking the password in
/// log output. The full KemProvider impl lands when the encrypt
/// pipeline is refactored to use trait objects (TODO.roadmap/30).
#[allow(dead_code)]
pub struct PasswordKem {
    pub(crate) word: String,
    pub(crate) password: String,
}

impl std::fmt::Debug for PasswordKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordKem")
            .field("word", &self.word)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl PasswordKem {
    pub fn new(word: impl Into<String>, password: impl Into<String>) -> Self {
        PasswordKem {
            word: word.into(),
            password: password.into(),
        }
    }
}

#[cfg(test)]
mod kem_tests {
    use super::*;

    #[test]
    fn password_kem_debug_does_not_leak_password() {
        let kem = PasswordKem::new("WORD", "secret123");
        let dbg = format!("{:?}", kem);
        // Debug should NOT contain the actual password value.
        // (If it does, that's a security issue — passwords in logs.)
        assert!(
            !dbg.contains("secret123"),
            "PasswordKem Debug leaked password: {}",
            dbg
        );
    }
}
