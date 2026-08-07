# 49 — Code coverage gate

**Priority**: P2
**Status**: specified

## Problem

CI runs `cargo llvm-cov` and uploads to Codecov, but:
- The result is informational only — no gate.
- Coverage can drop on a PR without anyone noticing.
- We don't track per-module coverage trends.

Without a gate:
- "Works on my machine" tests ship.
- Critical paths (crypto, parsing) may have low coverage.
- Refactors can silently drop coverage of edge cases.

## Goals

- Coverage is computed on every PR.
- A gate fails the build if total coverage drops by > 0.5%.
- Per-module coverage trends visible on Codecov dashboard.
- Coverage target: ≥ 85% overall, ≥ 95% for `src/crypto.rs`,
  `src/etree/parse.rs`, `src/cas.rs`.

## Design

### Coverage target by module

| Module | Target | Rationale |
|---|---|---|
| `src/crypto.rs` | ≥ 95% | Crypto bugs are catastrophic |
| `src/cipher.rs` | ≥ 95% | AEAD correctness |
| `src/etree/parse.rs` | ≥ 95% | Wire-format security |
| `src/etree/transform.rs` | ≥ 90% | State machine |
| `src/cas.rs` | ≥ 90% | Content addressing |
| `src/prot.rs` | ≥ 90% | Encrypt/decrypt correctness |
| `src/pbkdf.rs` | ≥ 85% | KDF correctness |
| `src/ledger/*` | ≥ 80% | Anchor DAG |
| `src/pki.rs` | ≥ 80% | Sign/verify |
| `src/cli/*` | ≥ 70% | Hard to test exhaustively |
| Overall | ≥ 85% | |

### CI gate

`.github/workflows/tests.yml` already uploads coverage. Extend the
`coverage` job:

```yaml
coverage:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v7
      with:
        fetch-depth: 0   # need base branch for diff
    - uses: dtolnay/rust-toolchain@stable
      with:
        components: llvm-tools-preview
    - run: ./ci/install.sh
    - uses: taiki-e/install-action@v2.85.3
      with:
        tool: cargo-llvm-cov
    - name: Generate coverage
      run: cargo llvm-cov --lcov --output-path lcov.info
    - name: Upload to Codecov
      uses: codecov/codecov-action@v4
      with:
        token: ${{ secrets.CODECOV_TOKEN }}
        files: lcov.info
        fail_ci_if_error: false
    - name: Coverage gate
      run: |
        # Compute coverage delta vs main
        BASE_COV=$(curl ... | jq .totals.percent_covered)
        HEAD_COV=$(jq .totals.percent_covered lcov.info)
        DELTA=$(echo "$HEAD_COV - $BASE_COV" | bc)
        if (( $(echo "$DELTA < -0.5" | bc -l) )); then
          echo "Coverage dropped by $DELTA% (threshold: -0.5%)"
          exit 1
        fi
```

### Local workflow

Developers run `cargo llvm-cov --open` to see a local HTML report
before pushing. This catches coverage regressions without waiting
for CI.

## Implementation plan

1. Verify the existing `coverage` job uploads correctly to Codecov.
2. Add per-module coverage targets as Codecov "carryforward" flags.
3. Add the gate step to the `coverage` job.
4. Document the local workflow in CONTRIBUTING.md.
5. Set initial baseline (current coverage) as the floor.

## Test plan

- [ ] `cargo llvm-cov` produces a complete report.
- [ ] Coverage gate fails when coverage drops by > 0.5%.
- [ ] Per-module targets are visible on Codecov dashboard.
- [ ] Local `cargo llvm-cov --open` works for developers.

## Out of scope

- Mutation testing (covered separately in TODO #43).
- Coverage of fuzz targets (the fuzz harness has its own metric).
- Coverage of language bindings (Python/Node/Go/Ruby have their own).
