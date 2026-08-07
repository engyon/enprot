# 44 — Snapshot testing harness (insta)

**Priority**: P2
**Status**: specified

## Problem

Many tests assert on serialized output:
- `tests/cli/*` invoke the binary and grep stdout.
- `tests/rsd-conformance/` checks parsed tree structure.
- JSON output tests compare against hand-written strings.

Hand-maintaining these expected outputs is brittle:
- Refactoring the output format requires editing N test files.
- "What did the output look like before?" is hard to visualise.
- Reviewers see `assert_eq!(actual, expected)` without the diff.

Snapshot testing (a.k.a. golden-file testing) captures the expected
output once; future runs diff against the snapshot. Refactoring the
output format updates one snapshot file with reviewer oversight.

## Goals

- `insta` crate integration for snapshot-based assertions.
- Snapshots live in `tests/snapshots/` (committed to git).
- A `cargo insta review` workflow lets developers approve changes.
- Existing string-comparison tests migrate to snapshots where the
  output is non-trivial.

## Design

### insta integration

`insta` is the de-facto Rust snapshot testing crate. Add to
`[dev-dependencies]`:

```toml
[dev-dependencies]
insta = { version = "1.41", features = ["yaml"] }
```

### Snapshot layout

```
tests/snapshots/
├── cli__encrypt_store_round_trip.txt
├── cli__inspect_basic.txt
├── cli__verify_chain_ok.txt
├── rsd__fixture_06_chain_anchor.txt
├── rsd__fixture_07_immutable.txt
└── ...
```

Each snapshot is the canonical output for one test. Filenames follow
`insta`'s convention (`<test_module>__<test_name>.<ext>`).

### Migration pattern

Before:

```rust
#[test]
fn inspect_basic() {
    let output = cmd("inspect basic.ept");
    assert_eq!(output, "== structure ==\n  BEGIN SECRET\n...");
}
```

After:

```rust
#[test]
fn inspect_basic() {
    let output = cmd("inspect basic.ept");
    insta::assert_snapshot!(output);
}
```

On the first run, `insta` creates `.pending` snapshots. Run
`cargo insta accept` to commit them. Future runs diff against the
committed snapshot; a change produces a `.pending` for review.

### When to use snapshots vs asserts

| Test type | Use snapshot? |
|---|---|
| Output is short, stable, hand-written | No — `assert_eq!` is clearer |
| Output is long, structured, machine-produced | Yes |
| Output changes per run (random IVs, timestamps) | No — unstable |
| Output is JSON / TOML / YAML | Yes (use `insta`'s redaction feature) |

### Redaction for unstable fields

Some output contains timestamps, random nonces, or hashes that
change per run. `insta` supports dynamic redaction:

```rust
insta::with_settings!({filters => vec![
    (r"\"ts\":\"[^\"]+\"", "\"ts\":\"<TS>\""),
    (r"\"nonce\":\"[^\"]+\"", "\"nonce\":\"<NONCE>\""),
]}, {
    insta::assert_snapshot!(json_output);
});
```

## Implementation plan

1. Add `insta` to `[dev-dependencies]`.
2. Migrate 5 high-value tests as a proof-of-concept:
   - `tests/cli/issue_15.rs` (CLI structural assertions)
   - `tests/rsd-conformance.rs` (parsed tree dumps)
   - `tests/cli/policy.rs` (policy output)
3. Add `cargo insta` to the dev workflow in CONTRIBUTING.md.
4. CI gate: `cargo insta test` passes with no `.pending` snapshots.

## Test plan

- [ ] `cargo test` runs snapshot assertions.
- [ ] Initial 5 migrated tests produce stable snapshots.
- [ ] A deliberate output change produces a reviewable `.pending`.
- [ ] `cargo insta accept` updates the committed snapshot cleanly.

## Out of scope

- Snapshot testing of binary output (PBKDF derived bytes, etc.).
  Use unit tests with byte arrays instead.
- Cross-version snapshot compatibility (snapshots are tied to the
  current version; old snapshots get regenerated on updates).
- A public snapshot registry (snapshots are internal test fixtures).
