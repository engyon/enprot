# 23 — Performance benchmarks vs alternatives

**Priority**: P2
**Status**: partial (existing benches/); comparison suite tracked here

## Problem

enprot has benchmarks (`benches/{crypto,merkle,parser}.rs`) measuring
internal performance. No comparison against alternatives (age, sops,
git-crypt, sequoia). Users evaluating tools can't answer "is enprot
fast enough for my use case?" with numbers.

## Goal

Public benchmark suite comparing enprot to:

| Alternative | Comparison axis |
|---|---|
| age | file encryption throughput |
| git-crypt | whole-file encryption, GPG path |
| sops | YAML/JSON encryption, per-key |
| sequoia-openpgp | OpenPGP sign + verify |
| sigstore (cosign) | artifact signing latency |

Plus internal micro-benchmarks:

- Parser throughput (MB/s of EPT input)
- CAS save/load (I/O bound)
- Chain anchor verification (DAG traversal)
- Transform latency (encrypt/decrypt per WORD)
- Deterministic AEAD vs random-nonce AEAD overhead

## Approach

### Internal benchmarks (extend existing `benches/`)

`benches/parser.rs` already exists. Add:

```rust
// benches/comparison.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn compare_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_1mb");
    group.bench_function("enprot_aes256siv", |b| b.iter(|| {
        enprot::prot::encrypt(/* 1MB plaintext */).unwrap()
    }));
    group.bench_function("age_aes256gcm", |b| b.iter(|| {
        age::encrypt(/* same plaintext */).unwrap()
    }));
    group.bench_function("git_crypt_aes256", |b| b.iter(|| {
        // subprocess to git-crypt for fairness
    }));
    group.finish();
}
```

### External comparison harness

`bench/compare.sh`:

```sh
#!/bin/sh
set -e
SIZE=${1:-1048576}  # 1MB default
INPUT=$(mktemp)
head -c $SIZE /dev/urandom > $INPUT

# enprot
time enprot encrypt -w Bench -k Bench=pw $INPUT -o $INPUT.enprot

# age
time age -p -o $INPUT.age $INPUT

# git-crypt (requires repo setup)
# time git-crypt encrypt $INPUT

# sops (requires YAML)
# time sops --encrypt --kms arn:... $INPUT

# cosign
time cosign sign-blob --key cosign.key $INPUT
```

Publishes results to `docs/performance.md` per release.

### CI: performance regression job

```yaml
bench-compare-main:
  if: github.event_name == 'pull_request'
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v7
      with: { fetch-depth: 0 }
    - run: ./ci/install.sh
    - run: cargo bench --bench comparison -- --save-baseline pr
    - run: git checkout origin/main
    - run: cargo bench --bench comparison -- --baseline pr
```

Criterion auto-prints regressions. Failures open issues.

## What we expect to find

Hypotheses (to be validated):

- **enprot vs age**: enprot slower on raw encrypt (more metadata:
  PHC string, structured cipher field). Within 2x.
- **enprot vs git-crypt**: enprot faster (no GPG fork).
- **enprot vs sops**: enprot faster on text (no YAML/JSON parse).
- **enprot vs sequoia**: comparable on OpenPGP sign (both use
  botan/sequoia primitives).
- **enprot vs cosign**: enprot faster on document signing (no
  network round-trip to Rekor).

## Acceptance criteria

- [ ] `benches/comparison.rs` with at least 4 comparisons
- [ ] `bench/compare.sh` harness
- [ ] `docs/performance.md` published per release
- [ ] CI regression job on PRs
- [ ] At least one external comparison in README (with link to
      methodology)

## Cross-references

- TODO.roadmap/05 — original benchmarks TODO
- [[14-streaming-io]] — affects large-file benchmarks
- [[03-readme-positioning]] — performance numbers in comparison table
