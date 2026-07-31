# 04 — Parallelize multi-file processing

**Priority**: P1
**Status**: specified

## Problem

`src/cli.rs:run()` processes multiple input files sequentially:

```rust
for (path_in, path_out) in files {
    process_one_file(&path_in, &path_out, &mut paops)?;
}
```

For a CI workflow that encrypts 200 source files (`enprot encrypt -w SECRET=pw src/**/*.toml`), this is ~200 × (parse + PBKDF derive + cipher + write) on a single core. On a 4-core CI runner that's a ~4× wall-clock tax — minutes of wasted build time per release.

`ParseOps` cannot move between threads today because:

- `Box<dyn CryptoPolicy>` — no `Send + Sync` bound on the trait.
- `Option<botan::RandomNumberGenerator>` — botan's RNG type is `Send` but not `Sync`.
- `Box<dyn CasStore>` — no `Send + Sync` bound on the trait.

## Goals

- `enprot encrypt FILE1 FILE2 ... FILEN` uses all available cores via `rayon`'s default thread pool.
- Wall-clock time scales inversely with core count, up to I/O saturation.
- No behavioral change vs. sequential processing: same output bytes, same CAS hashes, same error semantics.
- The PBKDF cache is shared across threads (a derive on thread A warms the cache for thread B).
- Drop-in: no new flags, no new public API.

## Non-goals

- **Per-file pipeline parallelism.** Parsing and transforming one file stays single-threaded; the parallelism is across files.
- **Async I/O.** Stay sync; `rayon`'s work-stealing is enough for the file-parallel case.
- **GPU acceleration.** Botan's AES-NI is already used; nothing more to do at this layer.

## Design

### Step 1: trait bounds

Add `Send + Sync` to `CryptoPolicy`:

```rust
// src/policy/mod.rs
pub trait CryptoPolicy: Send + Sync {
    fn check_hash(&self, alg: &str) -> Result<()>;
    fn check_pbkdf(&self, alg: &str) -> Result<()>;
    fn check_cipher_alg(&self, alg: &str) -> Result<()>;
    // …
}
```

Add `Send + Sync` to `CasStore`:

```rust
// src/cas.rs
pub trait CasStore: Send + Sync {
    fn save(&self, blob: &[u8], ctx: &CasCtx) -> Result<String>;
    fn load(&self, hash: &str, ctx: &CasCtx) -> Result<Vec<u8>>;
}
```

Existing impls (`NistPolicy`, `DefaultPolicy`, `LocalCas`) are already `Send + Sync` in practice — the bounds just make it compile-time-checked.

### Step 2: per-thread `ParseOps`

`ParseOps` is too richly mutable to share directly. Instead, each worker gets a clone of the *immutable* config parts (separators, transforms, passwords, crypto policy/opts) and its *own* RNG + PBKDF cache reference.

Introduce `ParseOpsTemplate` — the shareable, frozen view:

```rust
// src/etree/mod.rs

#[derive(Clone)]
pub struct ParseOpsTemplate {
    pub max_depth: usize,
    pub separators: Separators,
    pub transforms: Transforms,
    pub passwords: Arc<HashMap<String, String>>,
    pub crypto: CryptoConfigTemplate,
    pub io: IoConfigTemplate,
    pub anchor: AnchorConfig,
}

#[derive(Clone)]
pub struct CryptoConfigTemplate {
    pub policy: Arc<dyn CryptoPolicy>,
    pub pbkdfopts: PBKDFOptions,
    pub cipheropts: CipherOptions,
    pub pbkdf_cache: Arc<Mutex<PBKDFCache>>,
    pub recipient_pubs: Arc<Vec<String>>,
    pub recipient_privkeys: Arc<HashMap<String, String>>,
}

impl ParseOpsTemplate {
    /// Materialize a thread-local ParseOps that owns its RNG.
    pub fn instantiate(&self) -> Result<ParseOps> { /* … */ }
}
```

`run()` builds one `ParseOpsTemplate`, then:

```rust
template.instantiate_and_iter(files.par_iter().map(|(i, o)| (i, o)))
       .for_each(|result| results.push(result));
```

### Step 3: error aggregation

Sequential `?` short-circuits on the first error. Parallel needs to either:

1. Fail fast — first error wins, others are cancelled.
2. Collect all errors — useful for batch CI logs.

Default to fail-fast (matches current behavior). Add `--collect-errors` later if requested.

### Step 4: PBKDF cache sharing

```rust
pub type PBKDFCache = Arc<Mutex<HashMap<CacheKey, CacheVal>>>;
```

Lock contention is low: cache hits are no-ops (read-only), cache misses are rare (only first derivation per `(word, salt)` pair). Use `parking_lot::Mutex` for ~2× throughput over `std::sync::Mutex`.

### Step 5: optional opt-out

Some workflows want determinism (single-threaded ordering). Add `--jobs=1` flag that bypasses rayon's pool. Default: `--jobs=N` where N = num cores.

## Implementation plan

1. Add `Send + Sync` bounds to `CryptoPolicy` + `CasStore`. Audit all impls.
2. Introduce `ParseOpsTemplate` + `instantiate()`.
3. Convert `run()` to rayon `par_iter`.
4. Convert PBKDF cache to `Arc<Mutex<…>>`.
5. Add `--jobs` flag.
6. Benchmark before/after with `criterion` on a 200-file synthetic workload.

## Test plan

- [ ] Existing test suite still passes.
- [ ] New integration test: process 50 files in parallel; assert output bytes match sequential processing (deterministic ciphertext via `-det` ciphers).
- [ ] PBKDF cache hit-rate test: same WORD across 100 files → only 1 derivation.
- [ ] Benchmark: 4-core speedup ≥ 3.0× vs sequential.

## Risks

- **Botan RNG thread-safety.** Botan's RNG is `Send` but not `Sync` — each worker needs its own. `instantiate()` creates a fresh RNG per call.
- **CasStore contention.** `LocalCas` writes to the filesystem; concurrent writes to *different* paths are safe. Concurrent writes to *the same* path (dedup) are idempotent because content-addressed. Verify with a stress test.
- **Memory blowup.** N threads × per-file memory. Bound the thread count by available memory if file sizes are known.

## Out of scope

- Streaming I/O inside one file ([05-streaming-io]).
- Distributed/cluster processing (way out of scope; that's what Rekor CAS + Confium solve).
