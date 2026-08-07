# 41 — Benchmark suite expansion

**Priority**: P2
**Status**: specified

## Problem

`benches/` has three benches (`merkle`, `crypto`, `parser`) covering
hot primitives. Missing:

- **End-to-end pipeline benches** — parse → transform → write for
  representative file sizes (1 KB, 100 KB, 10 MB, 1 GB).
- **Parallel scaling benches** — `--jobs 1` vs `--jobs N` on a
  multi-file workload; verify the speedup is real.
- **CAS backend benches** — local-disk CAS read/write throughput
  for various blob sizes.
- **Memory profile** — peak RSS on large files (currently only
  implied via `time`).
- **Sigstore sign/verify benches** — ephemeral keypair + sign +
  verify cost (matters for CI pipelines that sign every commit).

CI's `Benchmarks` and `Benchmarks vs main` jobs run quick smoke
passes but don't capture scaling characteristics. A change that
adds 10% to per-file overhead is invisible.

## Goals

- `cargo bench` covers: primitives + pipeline + parallel + CAS + sigstore.
- Each bench produces a criterion report with a clear regression
  threshold (default: 5% slower = fail).
- A `--bench memory` target reports peak RSS via `dhat` or similar.
- `Benchmarks vs main` runs the full suite, not just three benches.

## Design

### New bench files

```
benches/
├── merkle.rs              (existing)
├── crypto.rs              (existing)
├── parser.rs              (existing)
├── pipeline_e2e.rs        (new — parse+transform+write)
├── parallel_scaling.rs    (new — --jobs 1 vs 4 vs 8)
├── cas.rs                 (new — local-disk CAS r/w)
├── sigstore.rs            (new — sign + verify round-trip)
└── memory.rs              (new — peak RSS on representative inputs)
```

### pipeline_e2e.rs shape

```rust
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use enprot::crypto::CryptoPolicyDefault;
use enprot::etree::{ParseOps, parse, transform, tree_write};

fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_e2e");
    for size in [1, 100, 10_000, 1_000_000].iter() {
        let input = synthetic_ept_file(*size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &input, |b, input| {
            b.iter(|| {
                let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
                paops.transforms.encrypt.insert("WORD".into());
                paops.passwords.insert("WORD".into(), "pw".into());
                let tree = parse(input.as_bytes(), &mut paops).unwrap();
                let tree = transform(&tree, &mut paops).unwrap();
                let mut out = Vec::new();
                tree_write(&mut out, &tree, &mut paops).unwrap();
            });
        });
    }
    group.finish();
}
```

### parallel_scaling.rs shape

```rust
fn bench_parallel(c: &mut Criterion) {
    let files: Vec<String> = (0..64).map(|i| synthetic_ept_file(10_000, i)).collect();
    for jobs in [1, 2, 4, 8].iter() {
        c.bench_function(&format!("parallel_jobs_{}", jobs), |b| {
            b.iter(|| process_files_parallel(&files, *jobs));
        });
    }
}
```

### memory.rs shape

```rust
// Uses dhat to track peak RSS.
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn bench_memory(c: &mut Criterion) {
    let prof = dhat::HeapStats::new();
    let input = synthetic_ept_file(1_000_000_000); // 1 GB
    let _ = process_pipeline(&input); // run once to measure
    let stats = prof.finish();
    eprintln!("peak RSS: {} MB", stats.max_bytes / 1_000_000);
}
```

### CI integration

`.github/workflows/benchmarks.yml` already runs the existing benches.
Extend the `--bench` invocations to include the new ones. Add a
`--bench memory` job gated behind a `large-runner` label (the 1 GB
bench needs >4 GB RAM).

## Implementation plan

1. Add `pipeline_e2e.rs` with 4 input sizes.
2. Add `parallel_scaling.rs` with `--jobs 1/2/4/8` variants.
3. Add `cas.rs` — `save`/`load` for 1 KB / 100 KB / 10 MB blobs.
4. Add `sigstore.rs` — Ed25519 sign + verify.
5. Add `memory.rs` using `dhat` for peak-RSS measurement.
6. Extend the CI workflow to run all benches.
7. Document benchmark interpretation in `docs/benchmarks.md`.

## Test plan

- [ ] `cargo bench` runs all 8 benches without error.
- [ ] Each bench produces a criterion HTML report.
- [ ] `Benchmarks vs main` reports regressions > 5%.
- [ ] `--bench memory` reports peak RSS for a 100 MB input.

## Out of scope

- Continuous profiling (e.g. flamegraphs in CI) — separate TODO.
- Benchmarks against other tools (age, gpg, sops) — requires a
  separate comparative harness.
- Hardware-specific benchmark normalisation.
