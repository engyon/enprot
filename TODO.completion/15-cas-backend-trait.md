# 15 — CAS backend trait

**Priority**: P2
**Status**: done (trait + local impl); new backends tracked separately

## Problem

`src/cas.rs` is hardcoded to the local filesystem:

```rust
pub fn save(blob: &[u8], paops: &ParseOps) -> Result<String> {
    let path = paops.io.casdir.join(hexhash);
    fs::write(path, blob)?;
    Ok(hexhash)
}
```

Users with multi-machine workflows want:
- **S3** (centralized CAS for distributed CI)
- **IPFS** (content-addressed P2P)
- **git-lfs** (existing infra)
- **Memory** (testing)
- **HTTP** (read-only mirror)

Today they'd have to fork enprot. The fix is a trait + registry.

## Solution

### Trait

```rust
pub trait CasStore: Send + Sync {
    /// Save a blob, return its content hash.
    fn save(&self, blob: &[u8]) -> Result<String>;

    /// Load a blob by hash. Errors if not present.
    fn load(&self, hash: &str) -> Result<Vec<u8>>;

    /// Check existence without loading.
    fn contains(&self, hash: &str) -> Result<bool>;
}

pub struct LocalCas { root: PathBuf }
pub struct S3Cas { bucket: String, prefix: String, client: S3Client }
pub struct IpfsCas { node_url: Url }
pub struct MemoryCas { entries: RwLock<BTreeMap<String, Vec<u8>>> }
```

### ParseOps integration

```rust
pub struct IoConfig {
    pub casdir: PathBuf,           // legacy: used by LocalCas
    pub cas: Box<dyn CasStore>,    // new: pluggable
    pub verbose: bool,
    pub inline_data: bool,
}
```

Default: `LocalCas` rooted at `casdir`. CLI flag for other backends:

```sh
enprot store --cas-backend s3://my-bucket/enprot-cas file.ept
enprot fetch --cas-backend ipfs://localhost:5001 file.ept
```

URL scheme picks the backend. Unknown scheme → typed Error.

### Migration path

- `cas::save(blob, paops)` becomes `paops.io.cas.save(blob)`.
- All existing call sites update.
- Existing users see no change (default backend is filesystem).

## Backends to ship

| Backend | Status | Use case |
|---|---|---|
| `LocalCas` | in this PR | default; filesystem |
| `MemoryCas` | in this PR | testing, library consumers |
| `S3Cas` | future | distributed CI |
| `IpfsCas` | future | P2P distribution |
| `GitLfsCas` | future | existing infra |
| `HttpCas` | future | read-only mirror |

## Acceptance criteria

- [x] `CasStore` trait defined in `src/cas.rs`
- [ ] `LocalCas` and `MemoryCas` impls
- [ ] `ParseOps.io.cas` field added; replaces `casdir` for save/load
- [ ] CLI `--cas-backend <URL>` flag
- [ ] Migration: existing call sites use the new trait method
- [ ] Tests: round-trip via LocalCas, MemoryCas

## Cross-references

- [[14-streaming-io]] — streaming variant of save/load
- [[22-performance-benchmarks]] — measure backend overhead
