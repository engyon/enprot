# 54 — Async pipeline option

**Priority**: P3
**Status**: specified

## Problem

enprot's pipeline is fully synchronous:

```rust
let tree = parse(reader, &mut paops)?;
let tree = transform(&tree, &mut paops)?;
tree_write(&mut writer, &tree, &mut paops)?;
```

Each step blocks the calling thread. For local files this is fine
(disk + CPU are fast). For networked CAS backends (#27), each
`cas::save`/`load` becomes a network round-trip — the thread
blocks waiting for the response.

With a sync pipeline:
- N parallel files need N threads.
- Each thread spends most of its time blocked on I/O.
- Throughput is limited by `--jobs` * (1 / network_latency).

An async pipeline would let a single thread multiplex many
in-flight CAS operations, dramatically improving throughput for
network-bound workloads.

## Goals

- An async variant of the pipeline: `async fn parse_async(...)`,
  `async fn transform_async(...)`, `async fn tree_write_async(...)`.
- Async CAS backends: `async fn save(...)`, `async fn load(...)`.
- The sync API stays as the default; async is opt-in via feature flag.
- The two paths share as much code as possible (no forking).

## Design

### Feature gate

```toml
[features]
async-pipeline = ["tokio", "async-trait"]
```

Default features stay sync. Consumers who want async add the
feature and use the async API.

### Async CAS trait

```rust
#[async_trait::async_trait]
pub trait AsyncCasStore: Send + Sync {
    async fn save_async(&self, blob: &[u8], policy: &dyn CryptoPolicy) -> Result<String>;
    async fn load_async(&self, hash: &str, policy: &dyn CryptoPolicy) -> Result<Vec<u8>>;
    async fn contains_async(&self, hash: &str, policy: &dyn CryptoPolicy) -> Result<bool>;
}

// LocalCas implements both CasStore (sync) and AsyncCasStore (async
// via spawn_blocking).
#[async_trait::async_trait]
impl AsyncCasStore for LocalCas {
    async fn save_async(&self, blob: &[u8], policy: &dyn CryptoPolicy) -> Result<String> {
        tokio::task::spawn_blocking({
            let blob = blob.to_vec();
            let this = self.clone();
            move || this.save(&blob, policy)
        }).await.map_err(|e| Error::Cas(format!("join error: {e}")))?
    }
    // ...
}

// S3Cas implements only AsyncCasStore (no sync variant — would
// require an internal tokio runtime).
```

### Async pipeline

```rust
pub async fn process_one_file_async<R: AsyncBufRead, W: AsyncWrite>(
    reader: &mut R,
    writer: &mut W,
    paops: &mut ParseOps,
) -> Result<()> {
    let tree = parse_async(reader, paops).await?;
    let tree = transform_async(&tree, paops).await?;
    tree_write_async(writer, &tree, paops).await?;
    Ok(())
}
```

Internally, `transform_async` awaits on `cas::load_async` for each
STORED block, allowing multiple blocks to be in-flight at once.

### Concurrency model

- Single-threaded async runtime (tokio current-thread): enough for
  I/O-bound workloads.
- Multi-threaded async runtime: useful when also doing CPU-bound
  crypto. Pair with `spawn_blocking` for the crypto step.
- The default `--jobs N` model (sync) stays; async is an alternative.

### When to use async vs sync

| Workload | Recommended |
|---|---|
| Local files only | Sync — no benefit from async |
| Networked CAS (S3, IPFS) | Async — high concurrency on I/O |
| Large files (streaming) | Sync streaming (#35) — async doesn't help with throughput |
| Many small files | Either; sync with `--jobs` is simpler |
| FFI consumers | Sync — async FFI is awkward |

## Implementation plan

1. Add `tokio` + `async-trait` as optional deps behind `async-pipeline`.
2. Define `AsyncCasStore` trait.
3. Implement `AsyncCasStore` for `LocalCas` (via `spawn_blocking`).
4. Add async variants of `parse`, `transform`, `tree_write` — share
   parsing logic via a generic-over-async helper.
5. Implement `process_one_file_async`.
6. Add `--async` CLI flag (experimental).
7. Benchmark: sync vs async on a networked CAS workload.

## Test plan

- [ ] `cargo build --features async-pipeline` succeeds.
- [ ] Async CAS round-trip matches sync output byte-for-byte.
- [ ] Async pipeline processes N files concurrently on one thread.
- [ ] No measurable overhead when async-pipeline is disabled.

## Out of scope

- Making the entire crate async-by-default (breaking change; defer).
- Async FFI (FFI consumers prefer sync).
- A `async_std` alternative to tokio (one runtime is enough).
- Per-block parallelism within a single file's transform (each block
  is small; the win is at the file level, not the block level).
