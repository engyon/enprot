# 05 — Performance benchmarks

**Priority**: P2
**Status**: specified

## Problem

No benchmarks. We can't detect performance regressions or compare
algorithms (Ed25519 vs ML-DSA, det-AEAD vs random-IV, Merkle tree
scaling). parsanol-rs has a `benches/` directory with criterion.

## Solution

### `benches/Cargo.toml` dev-dependency

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "crypto"
harness = false

[[bench]]
name = "parser"
harness = false

[[bench]]
name = "merkle"
harness = false
```

### Benchmark suites

**`benches/crypto.rs`**: keygen, sign, verify for Ed25519 vs ML-DSA.
KEM encapsulate/decapsulate when ML-KEM lands. PBKDF derivation timings.

**`benches/parser.rs`**: parse large EPT files (1k, 10k, 100k segments).
Transform round-trip. tree_write throughput.

**`benches/merkle.rs`**: tree construction from N leaves. Proof
generation + verification. O(N) vs O(log N) comparison for incremental
re-rooting.

### CI integration

```yaml
bench:
  name: Benchmarks
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v7
    - uses: dtolnay/rust-toolchain@stable
    - run: cargo bench --workspace -- --save-baseline main
    # On PRs: compare against main baseline
    - run: cargo bench --workspace -- --benchmark main
```

## Acceptance criteria

- [ ] `cargo bench` runs three suites
- [ ] Results checked into `docs/benches/` for trend tracking
- [ ] CI compares PR branch against main baseline
