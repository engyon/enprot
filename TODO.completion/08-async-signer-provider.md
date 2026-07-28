# 08 — Async SignerProvider / KemProvider traits

**Priority**: P0
**Status**: done (trait design); impl in 09

## Problem

`SignerProvider` today:

```rust
pub trait SignerProvider: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;
    fn fingerprint(&self) -> Result<KeyFp>;
}
```

Sync. Single message in, signature out. Fine for `PemSigner`.

**Doesn't fit Confium.** Confium's FROST threshold signing is
multi-round:
1. Each party broadcasts nonce commitments.
2. Each party receives commitments, derives binding factors,
   responds with share.
3. Aggregator combines shares, verifies.

That's 3 network round-trips. A `sign()` call on `ConfiumSigner`
must:
- Hold a session open across rounds.
- Coordinate with N remote parties via `confium-net`.
- Tolerate party timeouts.
- Produce the same `(SigAlgKind, Vec<u8>, KeyFp)` shape at the end.

A sync `sign()` blocks the caller for the entire protocol. For CLI
use that's tolerable; for library use (e.g. a CI bot signing 100
artifacts) it's a non-starter.

## Solution: dual trait

Keep `SignerProvider` (sync) for local-backends. Add
`AsyncSignerProvider` for network-backed backends. The CLI dispatches
through whichever the provider implements.

```rust
use std::future::Future;

/// Sync signing — single-party, local key material.
/// Implementors: PemSigner, future Pkcs11Signer (smartcard).
pub trait SignerProvider: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;
    fn fingerprint(&self) -> Result<KeyFp>;
}

/// Async signing — multi-party, network-backed, potentially slow.
/// Implementors: ConfiumSigner, future CloudKMSSigner.
#[async_trait::async_trait]
pub trait AsyncSignerProvider: Send + Sync {
    async fn sign_async(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;
    fn fingerprint(&self) -> Result<KeyFp>;
}
```

### Why not just make `SignerProvider` async?

Every consumer would need to be async. The parser, transform layer,
CLI — all would gain `async fn` pollution for a feature most users
don't need. Dual trait keeps sync consumers sync.

### Bridge helper

For consumers that want a single call site regardless of backend:

```rust
pub enum AnySigner {
    Sync(Box<dyn SignerProvider>),
    Async(Box<dyn AsyncSignerProvider>),
}

impl AnySigner {
    pub fn sign_blocking(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        match self {
            AnySigner::Sync(s) => s.sign(msg),
            AnySigner::Async(s) => {
                // Block on the async runtime. CLI uses this; library
                // users call .sign_async() directly.
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(s.sign_async(msg))
            }
        }
    }
}
```

### Same shape for KemProvider

```rust
#[async_trait::async_trait]
pub trait AsyncKemProvider: Send + Sync {
    async fn encapsulate_async(&self, recipient_pub: &[u8])
        -> Result<(Vec<u8>, Vec<u8>)>;  // (shared_secret, encapsulation)
    fn fingerprint(&self) -> Result<KeyFp>;
}
```

## What this enables

- `ConfiumSigner: AsyncSignerProvider` (TODO 09)
- `CloudKMSSigner: AsyncSignerProvider` (future)
- `ThresholdRng: AsyncRngProvider` (future)

CLI consumers don't change — `parse_signer_arg` returns
`AnySigner`, calls go through `sign_blocking()`. Library consumers
can pick the async path when they need it.

## Acceptance criteria

- [x] Trait design specified (this document)
- [ ] `async-trait` added to Cargo.toml
- [ ] `AsyncSignerProvider`, `AsyncKemProvider` traits added to `src/provider.rs`
- [ ] `AnySigner` enum + `sign_blocking` bridge added
- [ ] `parse_signer_arg` returns `AnySigner`
- [ ] Existing sync code paths still work
- [ ] Tests: sync backend via AnySigner, async backend via AnySigner

## Dependencies

- `async-trait = "0.1"` (proc-macro for async fn in traits on stable)
- `tokio = { version = "1", features = ["rt"] }` (for the blocking
  bridge; not required for library consumers)

## Cross-references

- [[09-confium-signer-architecture]] — first AsyncSignerProvider impl
- [[10-capability-threshold-provenance]] — capability model extension
- [[01-strategic-vision]] — why async matters for the integrated stack
