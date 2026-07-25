# Benchmarks

`cargo bench` runs three suites (TODO.roadmap/05). Each is `harness = false`
so criterion owns `main`:

- `benches/crypto.rs` — keygen/sign/verify across `SigAlgKind::ALL`
  (Ed25519, ML-DSA, CompositeEd25519MlDsa), ML-KEM encapsulate/decapsulate,
  Ed25519 sign+verify over a range of message sizes.
- `benches/merkle.rs` — tree construction, proof generation, proof
  verification across leaf counts {16, 256, 1024, 8192, 65536}. Proof
  ops should be `O(log N)`; tree build is `O(N)`.
- `benches/parser.rs` — `parse`, `tree_write`, and parse+write
  round-trip over files with {64, 512, 4096} WORD segments. The largest
  size is capped at 4096 because parser scaling is currently
  superlinear (4096 segments ≈ 600 ms; 32768 ≈ 41 s). Extend the range
  once the parser is `O(N)`.

## Running locally

```sh
cargo bench                                  # all suites, default settings
cargo bench --bench merkle                   # one suite
cargo bench -- --quick --warm-up-time 1      # fast smoke run
cargo bench -- --save-baseline before        # snapshot current numbers
# … make a change …
cargo bench -- --benchmark before            # compare against the snapshot
```

Criterion writes HTML reports to `target/criterion/<name>/report/index.html`.

## CI

`.github/workflows/tests.yml` has a `bench` job that compiles the
suites and runs them with `--quick` to catch regressions without
blocking PRs on perf noise. Snapshot baselines for trend tracking are
a future addition (TODO.roadmap/05).

## Reference numbers (Apple M-series, dev machine)

Numbers below are ballpark from a `--quick` run; treat as orders of
magnitude, not committed guarantees.

| op                       | ~time   |
| ------------------------ | ------- |
| Ed25519 keygen           | ~120 µs |
| Ed25519 sign (1 KiB)     | ~70 µs  |
| Ed25519 verify (1 KiB)   | ~105 µs |
| ML-DSA keygen            | ~1.5 ms |
| ML-DSA sign              | ~0.5 ms |
| ML-DSA verify            | ~1 ms   |
| ML-KEM encapsulate       | ~150 µs |
| ML-KEM decapsulate       | ~70 µs  |
| Merkle proof gen (64k)   | ~150 ns |
| Merkle proof verify (64k)| ~17 µs  |
| Parse 4k segments        | ~600 ms |
| tree_write 4k segments   | ~430 µs |
