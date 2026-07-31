# 06 — CAS backends (S3 + Rekor)

**Priority**: P1
**Status**: specified

## Problem

`CasStore` trait exists (TODO.completion/15) but only `LocalCas` (filesystem) is implemented. Users running multi-machine CI workflows want centralized CAS: S3, IPFS, or Rekor (transparency-log-backed).

## Goals

- `CasStore` trait implementations: `S3Cas`, `IpfsCas`, `RekorCas`.
- CLI: `enprot -c s3://my-bucket/enprot-cas/`, `enprot -c ipfs://Qm…`, `enprot -c rekor:`.
- Round-trip compatibility: same `(content)` → same hash regardless of backend.
- Backend swapping is a single-line change.

## Non-goals

- Hybrid backends (e.g., write local + S3). Future TODO.
- Encrypted-at-rest backends (CAS blobs are already ciphertext).

## Design

```rust
#[async_trait::async_trait]
pub trait CasStore: Send + Sync {
    async fn save(&self, blob: &[u8]) -> Result<String>;
    async fn load(&self, hash: &str) -> Result<Vec<u8>>;
    async fn exists(&self, hash: &str) -> Result<bool>;
}

pub struct LocalCas { root: PathBuf }
pub struct S3Cas { bucket: String, prefix: String, client: aws_sdk_s3::Client }
pub struct IpfsCas { gateway: url::Url, client: ipfs_api::IpfsClient }
pub struct RekorCas { client: sigstore::rekor::Client, /* … */ }

impl CasStore for LocalCas { /* … */ }
impl CasStore for S3Cas { /* … */ }
impl CasStore for IpfsCas { /* … */ }
impl CasStore for RekorCas { /* … */ }

/// Parse `-c` argument into a backend.
pub fn open_cas(spec: &str) -> Result<Box<dyn CasStore>> {
    match spec.split_once("://").map(|(s, _)| s) {
        None => Ok(Box::new(LocalCas::new(PathBuf::from(spec)))),
        Some("s3") => Ok(Box::new(S3Cas::from_url(spec)?)),
        Some("ipfs") => Ok(Box::new(IpfsCas::from_url(spec)?)),
        Some("rekor") => Ok(Box::new(RekorCas::new(spec)?)),
        Some(other) => Err(Error::InvalidArg { arg: "-c", reason: format!("unknown scheme: {other}") }),
    }
}
```

### Rekor backend specifics

`RekorCas` stores each blob as a PKIv2 entry in Rekor's transparency log. The hash returned is the entry's SHA-256, NOT the blob's content hash — so `RekorCas::load(hash)` actually does a Rekor lookup by entry hash, not a content fetch. Workaround: wrap the entry in a sidecar index that maps content-hash → entry-hash.

## Implementation plan

1. Add `async-trait` + `aws-sdk-s3` (optional, behind `s3` feature).
2. Refactor `LocalCas` to implement the new async trait (sync wrapper for back-compat).
3. Implement `S3Cas` + tests with `moto_server` (mock S3).
4. Implement `IpfsCas` + tests with `ipfsapi` mock.
5. Implement `RekorCas` (gated on [03-sigstore-keyless-signing]).
6. Update CLI to parse `-c <scheme>://...`.

## Test plan

- [ ] Local + S3 round-trip identical (content-hash stability).
- [ ] Rekor backend smoke test against staging.
- [ ] Concurrent writes to same hash from 4 threads → safe (idempotent or single-writer protocol).

## Out of scope

- Multi-region S3 replication.
- CDN-backed read paths (CloudFront signed URLs).
