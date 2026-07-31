//! Sigstore keyless signing for CHAIN anchors (TODO.complete/03).
//!
//! Status: **scaffold** — types and module layout defined, no signing
//! or verification logic yet. The actual implementation requires the
//! `sigstore-rs` crate (behind the `sigstore` cargo feature) and
//! pulls in tokio, openidconnect, x509-parser, picky, and a TUF
//! trust-root fetcher. That machinery lands in a follow-up once the
//! module's surface is reviewed.
//!
//! ## Design summary
//!
//! Sigstore keyless signs an artifact using a short-lived X.509 cert
//! issued by Fulcio, then records the signature in Rekor's
//! transparency log. The cert is obtained by presenting an OIDC
//! token (typically from GitHub Actions) that binds the signer's
//! identity (workflow URI, email) to a freshly generated key pair.
//!
//! In enprot, the artifact being signed is a CHAIN anchor's
//! signing payload (see `docs/schemas/chain-anchor-v1.md`):
//!
//! ```text
//! signing_payload(anchor) =
//!   index || parents || signer_alg || signer_fp || ts || payload_hash
//! ```
//!
//! The wire representation inside a CHAIN block gains a new extfield
//! `sig kind=sigstore-keyless cert=<PEM-b64> rekor=<url> sig=<hex>`,
//! parallel to the existing `pem-pgp` and `pem-ed25519` kinds.
//!
//! ## API surface (planned)
//!
//! - [`KeylessSigner`] — configured once per signing operation;
//!   produces a [`KeylessSignature`].
//! - [`verify()`] — validates a signature against a caller-supplied
//!   [`VerifyPolicy`] (OIDC issuer + identity regex + Fulcio root
//!   + Rekor public key).
//! - [`OidcSource`] — where to get the OIDC token (GitHub Actions
//!   environment, explicit token value, or token-file path).
//!
//! ## Why a stub
//!
//! This module compiles and exports types so downstream code
//! (CLI subcommands, FFI bindings, cookbook examples) can reference
//! the Sigstore API surface before the heavy implementation lands.
//! The `unimplemented!()` bodies make partial use easy to spot.

use std::path::PathBuf;

use crate::error::{Error, Result};
use url::Url;

/// Where to obtain the OIDC token for the signing operation.
#[derive(Debug, Clone, Default)]
pub enum OidcSource {
    /// Read from `$ACTIONS_ID_TOKEN_REQUEST_URL` +
    /// `$ACTIONS_ID_TOKEN_REQUEST_TOKEN` (GitHub Actions runtime).
    #[default]
    GitHubActions,
    /// Use an explicit JWT string (testing, custom OIDC providers).
    Token(String),
    /// Read the JWT from a file path (e.g., `$OIDC_TOKEN_FILE`).
    File(PathBuf),
}

/// Fulcio + Rekor endpoints. Defaults to the production Sigstore
/// instances; tests use the staging instances via [`Endpoints::staging`].
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub fulcio: Url,
    pub rekor: Url,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            fulcio: Url::parse("https://fulcio.sigstore.dev").expect("hardcoded URL"),
            rekor: Url::parse("https://rekor.sigstore.dev").expect("hardcoded URL"),
        }
    }
}

impl Endpoints {
    /// Public Sigstore staging environment. Free, doesn't pollute the
    /// production transparency log. Use for integration tests.
    pub fn staging() -> Self {
        Self {
            fulcio: Url::parse("https://fulcio.sigstage.dev").expect("hardcoded URL"),
            rekor: Url::parse("https://rekor.sigstage.dev").expect("hardcoded URL"),
        }
    }
}

/// Configuration for one keyless signing operation.
#[derive(Debug, Clone, Default)]
pub struct KeylessSigner {
    pub oidc: OidcSource,
    pub endpoints: Endpoints,
}

/// The output of a successful sign operation.
#[derive(Debug, Clone)]
pub struct KeylessSignature {
    /// Raw signature bytes (ECDSA P-256 over SHA-256 of the payload).
    pub signature: Vec<u8>,
    /// Fulcio-issued X.509 cert chain (PEM-encoded), binding the OIDC
    /// identity to the ephemeral public key.
    pub signing_cert: Vec<u8>,
    /// Rekor inclusion entry — publicly-auditable proof that the
    /// signature was recorded.
    pub rekor_entry: RekorEntry,
}

/// Rekor transparency-log entry for a Sigstore signature.
#[derive(Debug, Clone)]
pub struct RekorEntry {
    /// Monotonically-increasing log index.
    pub log_index: u64,
    /// Unix-seconds timestamp at which the entry was integrated.
    pub integrated_time: u64,
    /// Rekor's signed inclusion promise (a detached signature over
    /// the entry's hash, by Rekor's signing key).
    pub inclusion_promise: Vec<u8>,
    /// Optional Merkle inclusion proof (present for older entries
    /// and for entries explicitly requested with proof).
    pub inclusion_proof: Option<Vec<u8>>,
}

/// Trust policy for verification.
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
    /// Expected OIDC issuer URL (e.g.
    /// `https://token.actions.githubusercontent.com`).
    pub issuer: String,
    /// Regex the OIDC `sub` claim must match (e.g.
    /// `^github\.com/engyon/enprot/\.github/workflows/release\.yml@.*`).
    pub identity_regex: regex::Regex,
    /// Fulcio trust root (PEM-encoded root certs).
    pub fulcio_roots: Vec<Vec<u8>>,
    /// Rekor signing key (used to validate inclusion promises).
    pub rekor_public_key: Vec<u8>,
}

impl KeylessSigner {
    /// Sign `payload` using the configured OIDC source + endpoints.
    ///
    /// Returns the signature + the Fulcio cert + the Rekor inclusion
    /// entry. The caller serializes these into the CHAIN block's
    /// extfields.
    pub fn sign(&self, _payload: &[u8]) -> Result<KeylessSignature> {
        // TODO(sigstore): wire up sigstore-rs.
        // 1. Acquire OIDC token per `self.oidc`.
        // 2. Generate ephemeral ECDSA P-256 keypair.
        // 3. POST a CSR to Fulcio; receive signed cert.
        // 4. Sign `payload`; bundle with cert.
        // 5. Submit to Rekor; receive entry + inclusion promise.
        // 6. Return KeylessSignature.
        Err(Error::Msg(
            "sigstore::KeylessSigner::sign not yet implemented (TODO.complete/03)".into(),
        ))
    }
}

/// Verify a Sigstore keyless signature against a trust policy.
///
/// Checks (in order):
/// 1. Fulcio cert chain validates to a root in `policy.fulcio_roots`.
/// 2. Cert's OIDC `issuer` matches `policy.issuer`.
/// 3. Cert's OIDC `sub` matches `policy.identity_regex`.
/// 4. Signature verifies against the cert's public key.
/// 5. Rekor entry is present, included in the log, and signed by
///    `policy.rekor_public_key`.
pub fn verify(_payload: &[u8], _sig: &KeylessSignature, _policy: &VerifyPolicy) -> Result<()> {
    // TODO(sigstore): wire up sigstore-rs verification path.
    Err(Error::Msg(
        "sigstore::verify not yet implemented (TODO.complete/03)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_default_is_prod() {
        let e = Endpoints::default();
        assert!(e.fulcio.as_str().starts_with("https://fulcio.sigstore.dev"));
        assert!(e.rekor.as_str().starts_with("https://rekor.sigstore.dev"));
    }

    #[test]
    fn endpoints_staging_is_staging() {
        let e = Endpoints::staging();
        assert!(e.fulcio.as_str().contains("sigstage.dev"));
        assert!(e.rekor.as_str().contains("sigstage.dev"));
    }

    #[test]
    fn signer_returns_unimplemented_clearly() {
        let s = KeylessSigner::default();
        let err = s.sign(b"hello").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not yet implemented"),
            "expected clear unimplemented message, got: {msg}"
        );
        assert!(
            msg.contains("TODO.complete/03"),
            "expected pointer to the tracking TODO, got: {msg}"
        );
    }

    #[test]
    fn verify_returns_unimplemented_clearly() {
        let sig = KeylessSignature {
            signature: vec![],
            signing_cert: vec![],
            rekor_entry: RekorEntry {
                log_index: 0,
                integrated_time: 0,
                inclusion_promise: vec![],
                inclusion_proof: None,
            },
        };
        let policy = VerifyPolicy {
            issuer: "https://token.actions.githubusercontent.com".into(),
            identity_regex: regex::Regex::new(".*").unwrap(),
            fulcio_roots: vec![],
            rekor_public_key: vec![],
        };
        let err = verify(b"hello", &sig, &policy).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not yet implemented"));
        assert!(msg.contains("TODO.complete/03"));
    }
}
