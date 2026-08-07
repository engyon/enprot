# 43 — Mutation testing with cargo-mutants

**Priority**: P2
**Status**: specified

## Problem

Property tests and conformance fixtures verify behavior on inputs
the test author thought of. Mutation testing flips the question:
"if I introduce a bug, does a test catch it?"

`cargo-mutants` applies small mutations to source code (replace
`+` with `-`, `>` with `>=`, delete a `!`, etc.) and re-runs the
test suite. Mutations that don't fail any test indicate a test gap.

Without mutation testing:
- Refactors that silently change behavior ship to production.
- Code paths that look covered (high line coverage) aren't
  actually behavior-verified.
- The "did the test really check this?" question stays unanswerable.

## Goals

- A `cargo mutants` run on the enprot workspace that finishes in
  < 30 minutes on CI.
- Mutants are caught by ≥ 95% (i.e., uncaught mutants are reviewed
  individually).
- CI runs mutation testing on a weekly schedule (not per-PR — too
  slow).
- Each uncaught mutant is either:
  1. Turned into a new test that catches it, OR
  2. Documented as "equivalent mutant" (no semantic difference).

## Design

### Tool

`cargo-mutants` (https://github.com/sourcefrog/cargo-mutants) is
the de-facto Rust mutation testing tool. It works with the existing
test suite — no code changes needed.

### Configuration

```toml
# .cargo/mutants.toml (new)
# Skip modules where mutation is meaningless (FFI shims, error
# Display impls whose output isn't asserted, etc.).
exclude_modules = [
    "enprot_ffi::lib::*",          # FFI classifier — covered by integration tests
    "enprot::error::tests::*",     # Display tests — assert exact strings
]

# Cap runtime so CI doesn't burn hours.
timeout_secs = 300

# Generate mutations only in src/, not benches/ or examples/.
exclude_path = ["benches", "examples", "fuzz"]
```

### CI integration

`.github/workflows/mutants.yml` (new):

```yaml
name: mutation-testing
on:
  schedule:
    - cron: '0 3 * * 1'   # Mondays 03:00 UTC
  workflow_dispatch:

jobs:
  mutants:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: ./ci/install.sh
      - run: cargo install cargo-mutants
      - run: cargo mutants --in-place --jobs 4
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mutants-outcomes
          path: mutants.out*
```

The artifact (`mutants.out.json`) lists every mutant and whether it
was caught. The job doesn't fail the build (weekly information
gathering); failures are reviewed manually.

### Adding tests for uncaught mutants

When `cargo mutants` reports an uncaught mutant in `src/foo.rs`:

1. Read the mutation diff.
2. Decide: is this a real bug the test suite should catch?
   - **Yes**: add a test that fails when the mutation is present.
   - **No** (equivalent mutant, e.g., `x + 0` vs `x`): document in
     `.cargo/mutants.toml` as an excluded mutant.

## Implementation plan

1. Add `.cargo/mutants.toml` with sensible defaults.
2. Run `cargo mutants` locally on the parser module to baseline.
3. Add tests for any uncaught mutants found.
4. Add `.github/workflows/mutants.yml` weekly job.
5. Document the workflow in CONTRIBUTING.md (how to run locally,
  how to interpret results).

## Test plan

- [ ] `cargo mutants` runs to completion on the workspace.
- [ ] Initial baseline: ≥ 80% of mutants caught (target: 95%).
- [ ] Weekly CI job produces an artifact reviewable by maintainers.
- [ ] Equivalent mutants are documented, not silently ignored.

## Out of scope

- Mutation testing of `no_std` builds (defer until #14 WASM lands).
- Property-based mutation (mutating the input distribution, not the
  source code) — separate concern.
- Cross-language mutation (mutating FFI bindings) — out of scope.
