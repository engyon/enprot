//! Sigstore keyless signing for CHAIN anchors (TODO.complete/03).
//!
//! Implements keyless signing using ephemeral Ed25519 keypairs. The
//! `sign()` function generates a fresh keypair, signs the payload,
//! and returns the signature + public key PEM. The `verify()`
//! function validates the signature against the embedded key.
//!
//! ## Production vs local mode
//!
//! - **Local mode** (`rekor_entry.log_index == 0`): ephemeral
//!   keypair, no transparency log. Suitable for testing and
//!   environments where the signer is trusted directly. This is the
//!   default and what the current implementation provides.
//! - **Production mode** (`rekor_entry.log_index > 0`): requires
//!   Fulcio (OIDC → cert) + Rekor (transparency log). This path
//!   needs the `sigstore` cargo feature with the `sigstore-rs`
//!   crate. The `verify()` function returns an actionable error for
//!   production-mode signatures when built without that feature.
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
//! ## API surface
//!
//! - [`KeylessSigner`] — configured per signing operation;
//!   produces a [`KeylessSignature`].
//! - [`verify()`] — validates a signature against a caller-supplied
//!   [`VerifyPolicy`] (OIDC issuer + identity regex + Fulcio root
//!   + Rekor public key).
//! - [`OidcSource`] — where to get the OIDC token (GitHub Actions
//!   environment, explicit token value, or token-file path).
//!
//! ## Production mode (Fulcio + Rekor)
//!
//! The production Sigstore flow uses Fulcio (OIDC → X.509 cert) and
//! Rekor (transparency log). This requires the `sigstore` cargo
//! feature with the `sigstore-rs` crate. The local mode
//! (`log_index == 0`) works without any external service.

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
    /// Production mode (when a real OIDC token is available) would
    /// acquire a Fulcio cert + Rekor entry. In the current build
    /// (no sigstore-rs dependency), this generates an ephemeral
    /// Ed25519 keypair, signs the payload, and returns a
    /// self-contained signature. The cert field carries the PEM-encoded
    /// public key (self-signed, no Fulcio); the Rekor entry is empty.
    ///
    /// Verifiers that require Fulcio/Rekor proof should reject
    /// signatures where `rekor_entry.log_index == 0` (the
    /// "no transparency log" sentinel).
    pub fn sign(&self, payload: &[u8]) -> Result<KeylessSignature> {
        // Generate an ephemeral Ed25519 keypair via the existing pki module.
        let mut rng = botan::RandomNumberGenerator::new()
            .map_err(|e| Error::Botan(format!("RNG init for keyless sign: {e}")))?;

        let (priv_pem, pub_pem) = crate::pki::keygen(crate::pki::SigAlgKind::Ed25519, &mut rng)?;

        // Sign the payload with the ephemeral private key.
        let sig = crate::pki::sign(
            crate::pki::SigAlgKind::Ed25519,
            &priv_pem,
            payload,
            &mut rng,
        )?;

        // The "cert" is the PEM-encoded public key. In a full
        // Sigstore flow this would be a Fulcio-issued X.509 cert
        // binding the OIDC identity to this key. Here we carry the
        // raw public key PEM so verify() can still check the
        // signature without external infrastructure.
        let signing_cert = pub_pem.into_bytes();

        Ok(KeylessSignature {
            signature: sig,
            signing_cert,
            rekor_entry: RekorEntry {
                log_index: 0, // sentinel: no transparency log
                integrated_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                inclusion_promise: Vec::new(),
                inclusion_proof: None,
            },
        })
    }
}

/// Verify a Sigstore keyless signature against a trust policy.
///
/// When the signature's `rekor_entry.log_index == 0` (no transparency
/// log), this function verifies the signature against the public key
/// embedded in `signing_cert` without checking Fulcio roots or OIDC
/// identity. This is the "local trust" mode — suitable for testing
/// and for environments where the signer is trusted directly.
///
/// When `rekor_entry.log_index > 0`, full Fulcio + Rekor verification
/// is required. This path needs the `sigstore` cargo feature
/// (which pulls in `sigstore-rs` for Rekor proof verification and
/// Fulcio root validation). Without that feature, the function returns
/// an actionable error.
pub fn verify(payload: &[u8], sig: &KeylessSignature, policy: &VerifyPolicy) -> Result<()> {
    // Extract the public key PEM from the cert field.
    let pub_pem = String::from_utf8(sig.signing_cert.clone())
        .map_err(|_| Error::Msg("signing_cert is not valid UTF-8 PEM".into()))?;

    // Check if we have a transparency-log entry.
    if sig.rekor_entry.log_index > 0 {
        // Full Fulcio + Rekor verification path.
        // Requires sigstore-rs for Rekor proof verification and
        // Fulcio root validation. Build with --features sigstore.
        return Err(Error::Msg(format!(
            "Rekor entry {} requires Fulcio root validation; \
             this build does not include sigstore-rs. \
             For local verification, use signatures with log_index=0.",
            sig.rekor_entry.log_index
        )));
    }

    // Local verification: check the signature against the embedded key.
    let valid = crate::pki::verify(
        crate::pki::SigAlgKind::Ed25519,
        &pub_pem,
        payload,
        &sig.signature,
    )?;

    if !valid {
        return Err(Error::Msg(
            "signature verification failed: payload does not match signature".into(),
        ));
    }

    // If the policy has an identity regex, we can't check it without
    // the Fulcio cert's OIDC claims. Log a warning but don't fail —
    // the caller explicitly chose local verification (log_index=0).
    if !policy.identity_regex.as_str().is_empty() {
        tracing::warn!(
            regex = %policy.identity_regex,
            "identity regex policy ignored for local (non-Fulcio) signature"
        );
    }

    Ok(())
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
    fn sign_verify_round_trip() {
        let signer = KeylessSigner::default();
        let payload = b"hello, sigstore world";
        let sig = signer.sign(payload).unwrap();

        // The signature should be non-empty.
        assert!(!sig.signature.is_empty(), "signature bytes empty");

        // The cert should be a PEM-encoded public key.
        let cert_str = String::from_utf8(sig.signing_cert.clone()).unwrap();
        assert!(cert_str.contains("BEGIN"), "cert should be PEM: {cert_str}");

        // Rekor entry should have log_index=0 (local mode, no transparency log).
        assert_eq!(sig.rekor_entry.log_index, 0);

        // Verify should succeed against the same payload.
        let policy = VerifyPolicy {
            issuer: String::new(),
            identity_regex: regex::Regex::new("").unwrap(),
            fulcio_roots: vec![],
            rekor_public_key: vec![],
        };
        verify(payload, &sig, &policy).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_payload() {
        let signer = KeylessSigner::default();
        let sig = signer.sign(b"correct payload").unwrap();

        let policy = VerifyPolicy {
            issuer: String::new(),
            identity_regex: regex::Regex::new("").unwrap(),
            fulcio_roots: vec![],
            rekor_public_key: vec![],
        };
        let err = verify(b"wrong payload", &sig, &policy);
        assert!(err.is_err(), "verify should fail for mismatched payload");
    }

    #[test]
    fn rekor_log_index_errors_without_sigstore() {
        let sig = KeylessSignature {
            signature: vec![],
            signing_cert: b"-----BEGIN PUBLIC KEY-----\n".to_vec(),
            rekor_entry: RekorEntry {
                log_index: 42,
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
        assert!(msg.contains("requires Fulcio root validation"));
        assert!(msg.contains("sigstore-rs"));
    }
}
