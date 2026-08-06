# 32 — Sigstore keyless: full Fulcio + Rekor integration

**Priority**: P1
**Status**: specified (continuation of #03)

## Problem

`src/sigstore.rs` ships a real Ed25519 sign/verify path (~340 lines):
`KeylessSigner::sign()` generates an ephemeral keypair and signs;
`verify()` checks the signature against the embedded public key when
`log_index == 0`. The `log_index > 0` case returns an actionable
error: "needs Fulcio/Rekor". This is the gap.

To reach true keyless signing (the signature story for CI pipelines),
enprot needs to:

1. At sign time: get a Fulcio signing cert (proves the ephemeral key
   belongs to the claimed identity), then append a Rekor entry
   (transparency log).
2. At verify time: download the Fulcio cert by Rekor log index,
   verify the signature against the cert's public key, verify the
   cert chain to Fulcio root, verify the Rekor inclusion proof.

The local-only `log_index == 0` path is a developer convenience; it
doesn't satisfy the "keyless" guarantee (anyone could forge a key).

## Goals

- `enprot attest --sigstore-keyless --identity <id>` produces a
  CHAIN anchor with a Fulcio-issued cert and a Rekor entry.
- `enprot verify-chain --sigstore-keyless --identity <id> <file>`
  verifies the anchor end-to-end: cert chain to Fulcio root + Rekor
  inclusion proof + signature against cert pubkey.
- Identities supported: GitHub Actions OIDC token, email (via
  Dex/Google), SPIFFE.
- No long-lived keys on disk; the signing key lives only for the
  duration of one `attest` invocation.

## Design

### Backend selection

Behind a `sigstore` feature:

```toml
[features]
sigstore = ["sigstore-rs", "openidconnect"]
```

`sigstore-rs` already exists as a dep (PR #220). The feature flag
gates the network code.

### Sign flow

```rust
// src/sigstore.rs (extended)
pub struct KeylessSigner {
    identity: Identity,
    fulcio_url: Url,
    rekor_url: Url,
}

impl KeylessSigner {
    pub async fn sign(&self, payload: &[u8]) -> Result<SignedBundle> {
        // 1. Get an OIDC token for the identity.
        let token = self.identity.token().await?;

        // 2. Generate ephemeral Ed25519 key.
        let (privkey, pubkey) = ed25519_keypair()?;

        // 3. Build CSR with the pubkey + identity.
        let csr = build_csr(&privkey, &self.identity)?;

        // 4. POST CSR + token to Fulcio → get signing cert chain.
        let cert_chain = fulcio_sign(&self.fulcio_url, csr, token).await?;

        // 5. Sign payload with privkey.
        let signature = ed25519_sign(&privkey, payload)?;

        // 6. POST {payload, signature, cert_chain} to Rekor → get entry.
        let entry = rekor_append(&self.rekor_url, payload, &signature, &cert_chain).await?;

        Ok(SignedBundle {
            signature,
            cert_chain,
            rekor_log_index: entry.log_index,
            rekor_integrated_time: entry.integrated_time,
        })
    }
}
```

### Verify flow

```rust
pub async fn verify(bundle: &SignedBundle, payload: &[u8]) -> Result<()> {
    // 1. Fetch the Rekor entry by log_index.
    let entry = rekor_get(bundle.rekor_log_index).await?;

    // 2. Verify the Rekor inclusion proof (Merkle path).
    entry.verify_inclusion_proof()?;

    // 3. Extract the cert from the entry.
    let cert = entry.cert()?;

    // 4. Verify cert chain to Fulcio root.
    cert.verify_chain(FULCIO_ROOT_CERTS)?;

    // 5. Verify the signature against the cert's pubkey.
    cert.verify_signature(payload, &bundle.signature)?;

    Ok(())
}
```

### CLI integration

```
enprot attest --sigstore-keyless
              --identity "github-actions://workflow=ci"
              [--fulcio-url https://fulcio.sigstore.dev]
              [--rekor-url https://rekor.sigstore.dev]
              FILE

enprot verify-chain --sigstore-keyless
                    --identity "github-actions://workflow=ci"
                    FILE
```

The `--identity` flag picks the OIDC source. For GitHub Actions, the
OIDC token is in `$ACTIONS_ID_TOKEN_REQUEST_TOKEN` + the request URL;
enprot fetches the token at startup. For local dev, an interactive
OAuth flow (browser) gets a Google/Dex token.

### Identity model

```rust
pub enum Identity {
    GithubActions { workflow: String },
    Email { address: String, provider: Url },
    Spiffe { id: String },
}

impl Identity {
    async fn token(&self) -> Result<OidcToken> {
        match self {
            Self::GithubActions { workflow } => gh_oidc_token(workflow).await,
            Self::Email { address, provider } => email_oauth(address, provider).await,
            Self::Spiffe { id } => spiffe_token(id).await,
        }
    }
}
```

## Implementation plan

1. Land `sigstore-rs` integration behind `sigstore` feature.
2. Implement `Identity` enum + per-variant token fetchers.
3. Implement Fulcio sign path.
4. Implement Rekor append + inclusion-proof verify.
5. Wire `enprot attest --sigstore-keyless`.
6. Wire `enprot verify-chain --sigstore-keyless`.
7. Integration tests (require network; gated on `sigstore-net` feature + `CI=1`).
8. Documentation: `docs/sigstore.md` with setup instructions per identity.

## Test plan

- [ ] `cargo test --features sigstore` passes with no network (mock Fulcio/Rekor).
- [ ] `cargo test --features sigstore-net` runs against the real
  `sigstore.dev` infrastructure (CI-only; gated to avoid burning rate limits).
- [ ] Round-trip: `attest` then `verify-chain` succeeds with the
  resulting CHAIN anchor.
- [ ] Negative test: tampering with the payload causes verify to fail.
- [ ] Negative test: a different identity's verify fails.

## Out of scope

- Air-gapped signing (no Fulcio/Rekor) — covered by the existing
  local `log_index == 0` path.
- HSM-backed signing keys — separate TODO.
- A `enprot sigstore keys` subcommand for managing local OIDC caches.
