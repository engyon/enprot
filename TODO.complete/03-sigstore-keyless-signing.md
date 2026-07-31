# 03 — Sigstore keyless signing

**Priority**: P1
**Status**: specified

## Problem

enprot's CHAIN anchor system already supports signatures — Ed25519, ML-DSA, composite Ed25519+ML-DSA — but every signature kind requires the signer to pre-provision a private key and the verifier to obtain the public key out-of-band. That works for individual release engineers (one PEM file) but breaks down for:

1. **CI-issued signatures.** A release workflow that transforms files (encrypt-on-publish, store-to-CAS) needs to sign the resulting CHAIN anchor so downstream consumers can verify the release pipeline produced the artifact. Distributing a persistent private key to every CI runner is the exact failure mode Sigstore exists to fix.
2. **Cross-org verification.** A buyer at a different organization can't easily obtain the signer's public key. They want to verify against a stable, publicly-auditable identity (email, workflow URI) instead.
3. **Key rotation.** A release engineer's laptop key compromise should not invalidate old signatures. Sigstore's per-artifact ephemeral keys solve this by construction.

Sigstore keyless (Fulcio + Rekor + OIDC) is the standard solution. It slots cleanly into enprot's existing CHAIN anchor format because the anchor already carries arbitrary signature material in its extfields.

## Goals

- `enprot attest --sigstore-keyless` signs the current file's CHAIN anchor using a Fulcio-issued ephemeral cert, derived from the caller's OIDC identity (GitHub Actions by default; other OIDC providers configurable).
- `enprot verify --sigstore` verifies a Sigstore signature against the configured Fulcio root + the caller's identity policy.
- The CHAIN wire format gains a new signer kind, `sigstore-keyless`, that bundles the signature, the ephemeral Fulcio cert chain, and the Rekor inclusion proof.
- No private key custody in CI. No pre-provisioned keys for the signer. No public key distribution for the verifier (beyond Fulcio's well-known root).
- Transparency log entries are non-revocable: an attacker who later compromises the signer cannot erase evidence of a past signature.

## Non-goals

- **Encryption to Fulcio certs.** Technically possible via ECDH but operationally broken — Fulcio certs live ~10 minutes. enprot's confidentiality layer stays WORD/password + ML-KEM recipients.
- **Replacing the existing PEM-key PKI.** Sigstore becomes a *new signer kind*, not a replacement. PEM-key signing continues to work for users who need persistent identities.
- **Custom OIDC provider support in the first cut.** GitHub Actions only; generalize when there's a second real use case.
- **Threshold signing with Sigstore + hardware.** Belongs to Confium, not enprot.

## Design

### New cargo feature

```toml
[features]
sigstore = ["dep:sigstore-rs"]
```

Gated because:
- `sigstore-rs` pulls in `picky`, `tokio`, `openidconnect`, `x509-parser` — heavy.
- Browser/edge WASM build doesn't need it.
- Most users on the document edge won't sign in CI; the feature is opt-in.

### Wire format

A CHAIN anchor's signer list gains a third kind alongside `pgp` and `pem-key`:

```
// <( CHAIN anchor )>
// <( prev:abc... )>
// <( sig kind=sigstore-keyless
//      issuer="https://token.actions.githubusercontent.com"
//      identity="github.com/engyon/enprot/.github/workflows/release.yml@refs/tags/enprot-v0.5.13"
//      cert="MII...sigstore-fulcio-cert..."
//      rekor="https://rekor.sigstore.dev/api/v1/log/entries/12345..."
//      sig="MEUCIQD..." )>
// <( END anchor )>
```

Same `DATA`-style line wrapping as other large extfield values (48-char chunks of base64).

### PKI module additions

```rust
// src/pki.rs

#[cfg(feature = "sigstore")]
pub mod sigstore {
    use crate::error::{Error, Result};

    /// Configuration for one keyless signing operation.
    #[derive(Debug, Clone)]
    pub struct KeylessSigner {
        pub oidc: OidcSource,
        pub fulcio_url: url::Url,   // default: Fulcio prod
        pub rekor_url: url::Url,    // default: Rekor prod
    }

    #[derive(Debug, Clone)]
    pub enum OidcSource {
        /// GitHub Actions: read from $ACTIONS_ID_TOKEN_REQUEST_*
        GitHubActions,
        /// An explicit token value (testing / non-GH environments).
        Token(String),
        /// Token-file path (e.g. $OIDC_TOKEN_FILE).
        File(std::path::PathBuf),
    }

    pub struct KeylessSignature {
        pub signature: Vec<u8>,         // the artifact signature (ECDSA P-256)
        pub signing_cert: Vec<u8>,      // Fulcio-issued X.509 cert chain (PEM)
        pub rekor_entry: RekorEntry,
    }

    pub struct RekorEntry {
        pub log_index: u64,
        pub integrated_time: u64,
        pub inclusion_promise: Vec<u8>,
        pub inclusion_proof: Option<Vec<u8>>,
    }

    impl KeylessSigner {
        pub fn sign(&self, payload: &[u8]) -> Result<KeylessSignature> { /* … */ }
    }

    pub fn verify(
        payload: &[u8],
        sig: &KeylessSignature,
        policy: &VerifyPolicy,
    ) -> Result<()> { /* … */ }

    #[derive(Debug, Clone)]
    pub struct VerifyPolicy {
        pub issuer: String,                              // expected OIDC issuer URL
        pub identity_regex: regex::Regex,               // expected subject identity
        pub fulcio_roots: rustls_pemfile::Certificates, // Fulcio trust root
        pub rekor_public_key: Vec<u8>,                  // Rekor signing key
    }
}
```

### CLI

```
enprot attest --sigstore-keyless [--sigstore-oidc=github-actions|token:...|file:...]
                                [--sigstore-fulcio-url=URL]
                                [--sigstore-rekor-url=URL]
                                [--sigstore-issuer=URL]
                                [--sigstore-identity-regex=REGEX]
                                file.ept
```

Verify:

```
enprot verify --sigstore [--sigstore-issuer=URL] [--sigstore-identity-regex=REGEX] file.ept
```

### CI integration recipe

```yaml
permissions:
  contents: read
  id-token: write   # required for OIDC

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: enprot attest --sigstore-keyless file.ept
```

The `id-token: write` permission is what makes `ACTIONS_ID_TOKEN_REQUEST_*` env vars available to enprot.

### Testing

- **Unit tests** in `src/pki.rs::sigstore::tests` cover:
  - OIDC token parsing (JWT structure, claim extraction)
  - Cert chain validation against Fulcio root (mock CA)
  - Rekor inclusion proof verification
- **Integration test** uses Sigstore's **staging** environment (`fulcio.sigstage.dev`, `rekor.sigstage.dev`) — public, free, doesn't pollute prod transparency logs.
- **End-to-end test** in `tests/cli/sigstore.rs` round-trips sign + verify in staging.

### Trust root distribution

`enprot verify --sigstore` needs Fulcio's root cert + Rekor's public key. The TUF repository at `https://tuf-repo-cdn.sigstore.dev` is the canonical source. Cache to `~/.cache/enprot/sigstore-trust-root.json`; refresh every 24h; allow override via `--sigstore-trust-root=path`.

## Implementation plan

1. Add `sigstore` feature + dependency in `Cargo.toml`.
2. Add `src/pki/sigstore.rs` with `KeylessSigner` + `verify`.
3. Extend the CHAIN extfield parser to recognize `sigstore-keyless` as a new signer kind.
4. Add `enprot attest --sigstore-keyless` subcommand.
5. Add `enprot verify --sigstore` path.
6. Trust root fetcher + cache.
7. CI workflow to test the round-trip on staging.

## Test plan

- [ ] `cargo test --features sigstore` passes locally.
- [ ] Staging-environment end-to-end test runs in CI.
- [ ] Documentation: `docs/sigstore.md` with the recipe above.
- [ ] Cookbook entry: "Sign a release artifact with Sigstore keyless" in `docs/cookbooks/`.

## Out of scope

- Signing arbitrary blobs (not just CHAIN anchors). Future: `enprot sign --sigstore-keyless --detached file.bin > file.sig`.
- Multiple Sigstore signatures per CHAIN (one per workflow run). For now, append new anchors per run.
- Rekor CAS backend (separate TODO, [06-cas-backends]).
- Custom OIDC provider discovery (start with GitHub Actions; generalize later).
