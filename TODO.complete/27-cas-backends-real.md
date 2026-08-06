# 27 — Real CAS backends: S3 + IPFS + Rekor

**Priority**: P1
**Status**: specified

## Problem

`src/cas.rs::open_cas(spec)` currently dispatches on the URL scheme:

| Spec prefix     | Backend       | Status |
|-----------------|---------------|--------|
| (local path)    | `LocalCas`    | ✅ shipped |
| `memory:`       | `MemoryCas`   | ✅ shipped (test-only) |
| `s3://...`      | —             | ❌ actionable error |
| `ipfs://...`    | —             | ❌ actionable error |
| `rekor://...`   | —             | ❌ actionable error |

The actionable errors ("requires `--features cas-s3`") are accurate
but the backends themselves don't exist. Real backends unblock:

- **Supply-chain provenance**: a `manifest` run in CI publishes
  content blobs to S3, then signs the manifest head with a CHAIN
  anchor. Verifiers fetch blobs from S3 by hash.
- **Distributed teams**: IPFS lets a team share CAS content
  peer-to-peer without a central server.
- **Transparency log**: Rekor integrates enprot blobs into a public
  append-only log for non-repudiation.

## Goals

- All three backends behind **feature flags** (`cas-s3`, `cas-ipfs`,
  `cas-rekor`), so the default build stays lean.
- Each backend implements the existing `CasBackend` trait
  (`save`, `load`, `exists`).
- `LocalCas`-compatible behavior: idempotent `save`, content-addressed
  (`hash == sha3-256(content)`), no partial writes.
- One integration test per backend, gated on feature flag + env vars
  (CI runs LocalCas only; backend tests run on demand with creds).
- Documentation: a new `docs/cas-backends.md` with setup instructions
  per backend.

## Design

### Trait extension (no breaking change)

`CasBackend` already exists; just make sure all three methods are
`&self` and async-friendly via a sync wrapper (don't introduce async
into the core pipeline; keep backends blocking with internal retries).

```rust
// src/cas.rs (existing)
pub trait CasBackend: Send + Sync {
    fn save(&self, blob: &[u8], paops: &ParseOps) -> Result<String>;
    fn load(&self, hash: &str, paops: &ParseOps) -> Result<Vec<u8>>;
    fn exists(&self, hash: &str, paops: &ParseOps) -> Result<bool>;
}
```

### S3 backend (`cas-s3` feature)

```rust
// src/cas/backends/s3.rs (new)
pub struct S3Cas {
    bucket: String,
    prefix: String,
    client: aws_sdk_s3::Client,
}

impl S3Cas {
    pub fn from_url(url: &str) -> Result<Self> {
        // s3://bucket/prefix → bucket + prefix
    }
}

impl CasBackend for S3Cas {
    fn save(&self, blob: &[u8], _paops: &ParseOps) -> Result<String> {
        let hash = hex::encode(sha3_256(blob));
        let key = format!("{}/{}", self.prefix, hash);
        self.client.put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(blob.to_vec()))
            .send()
            .map_err(|e| Error::Cas(format!("S3 put_object: {e}")))?;
        Ok(hash)
    }
    // load, exists: similar
}
```

**Dependency**: `aws-sdk-s3 = "1.40"` (behind `cas-s3` feature).

**Credential resolution**: standard AWS chain (env vars, shared-credentials file, IAM role). No enprot-specific config.

### IPFS backend (`cas-ipfs` feature)

Uses the IPFS HTTP RPC API (`/api/v0/v1/add`, `/cat`).

```rust
// src/cas/backends/ipfs.rs
pub struct IpfsCas {
    api_url: Url,           // http://localhost:5001
    gateway_url: Url,       // https://ipfs.io
    pin: bool,              // pin on save (default true)
}
```

IPFS uses CIDv1 (content identifier), not raw SHA3-256. Wrap:
`hash = sha3-256(blob)`, but store under CID with the SHA3-256
multihash. The CAS trait returns the SHA3-256 hex; the backend tracks
a `sha3_hex ↔ CID` mapping internally.

**Dependency**: `reqwest = "0.12"` + `serde_json` (already in tree).

### Rekor backend (`cas-rekor` feature)

Rekor is a transparency-log service. Each `save` creates a Rekor
entry (signed by enprot's key), returning the entry ID.

This backend is **write-mostly**: `load` fetches the blob from the
signer's out-of-band storage (Rekor stores only hashes, not content).
For enprot's purpose, Rekor is best modeled as a **transparency log
layer** rather than a primary CAS. Consider modelling it as:

```rust
pub struct RekorTlog {
    inner: Box<dyn CasBackend>,  // delegate storage to Local/S3/IPFS
    rekor_url: Url,
    signer_pem: String,
}
```

Every `save` writes locally AND appends to Rekor. `load` reads from
the inner backend. `verify_in_rekor(hash)` is a separate method on
`RekorTlog`, not part of the trait.

**Dependency**: `reqwest` + `pem` + `sigstore-rs` (already a dep for #03).

## Implementation plan

1. Create `src/cas/backends/` module directory.
2. Move `LocalCas` and `MemoryCas` into `src/cas/backends/local.rs`
   and `src/cas/backends/memory.rs` (no behavior change, just
   module re-org for OCP).
3. Land S3 backend behind `cas-s3` feature. Gate `open_cas` match
   arm behind `#[cfg(feature = "cas-s3")]`.
4. Land IPFS backend behind `cas-ipfs` feature.
5. Land Rekor backend behind `cas-rekor` feature.
6. Integration tests in `tests/cas_backends/` — each gated on feature
   + env vars.
7. `docs/cas-backends.md` with setup instructions.

## Test plan

- [ ] Default features: `cargo test` passes (LocalCas only).
- [ ] `cargo test --features cas-s3` passes locally with AWS creds in env.
- [ ] `cargo test --features cas-ipfs` passes locally with IPFS daemon running.
- [ ] `cargo test --features cas-rekor` passes locally with Rekor URL set.
- [ ] Each backend round-trips 1 KB, 1 MB, 100 MB blobs identically to LocalCas.
- [ ] Concurrent `save(blob)` and `save(blob)` from two threads produces one entry, not two (idempotency).

## Out of scope

- Backend-specific authentication flows beyond the standard chain.
- Backend-specific TLS pinning — use rustls default.
- A unified CLI for `enprot cas push --to s3://...` — separate TODO.

## Future hooks

- A `--cas-mirror` flag that fans out saves to N backends (mirroring).
- A `--verify-in-rekor` flag that checks a hash has a transparency entry.
- Async backends (would require async trait methods; defer until perf proves it's needed).
