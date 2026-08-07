# 64 — Formal verification for critical paths

**Priority**: P3
**Status**: specified

## Problem

enprot's crypto dispatch and CAS verification are tested with
property tests + conformance fixtures. Tests show the code works
on the inputs we thought of. They don't prove the code is correct
on ALL inputs.

For critical paths — the ones where a bug means data loss or
security breach — formal verification provides mathematical
guarantees:

- **Parser correctness**: `parse(unparse(tree)) == tree` for all
  valid trees. (Round-trip property, but proven, not just tested.)
- **CAS content addressing**: `load(save(blob)) == blob` for all
  blobs. And `save(b1) == save(b2) ⟹ b1 == b2`.
- **Transform idempotency**: `encrypt(encrypt(file)) == encrypt(file)`
  for the `-det` variant. Proven, not just property-tested.

Tools like [Verus](https://github.com/verus-lang/verus) and
[Prusti](https://www.pm.inf.ethz.ch/research/prusti.html) can verify
Rust code against specifications, catching bugs tests miss.

## Goals

- Formal specifications for 3 critical functions: `cas::save`/`load`
  round-trip, `etree::parse`/`tree_write` round-trip, and
  `prot::encrypt`/`decrypt` round-trip.
- Verification runs in CI (weekly, not per-PR — too slow).
- Verification failures are treated as P0 bugs.
- The specs serve as machine-checked documentation of invariants.

## Design

### Tool choice: Verus

Verus supports a subset of Rust and can verify:
- Memory safety (no panics, no overflows).
- Functional correctness (preconditions, postconditions, invariants).
- Termination (for recursive functions).

It compiles to SMT (Z3) and runs in seconds to minutes per function.

### Specification approach

Annotate the critical functions with `requires`/`ensures` clauses:

```rust
verus! {
    pub fn save(blob: &[u8], policy: &dyn CryptoPolicy) -> (result: Result<String, Error>)
        ensures
            result.is_ok() ==> forall |i: int|
                0 <= i < blob.len() ==> true,  // hash is deterministic
    {
        // ... implementation ...
    }

    pub fn load(hexhash: &str, policy: &dyn CryptoPolicy) -> (result: Result<Vec<u8>, Error>)
        ensures
            // If save returned Ok(hash), then load(hash) returns the original blob.
            forall |blob: Vec<u8>|
                save(&blob, policy).is_ok() ==> {
                    let hash = save(&blob, policy).unwrap();
                    load(&hash, policy).is_ok() &&
                    load(&hash, policy).unwrap() =~= blob
                },
    {
        // ... implementation ...
    }
}
```

### Scope: what to verify

| Function | Property | Priority |
|---|---|---|
| `cas::LocalCas::save` + `load` | `load(save(b)) == b` | P0 |
| `cas::MemoryCas::save` + `load` | Same | P0 |
| `etree::parse` + `tree_write` | Round-trip for valid trees | P1 |
| `prot::encrypt` + `decrypt` (det) | `decrypt(encrypt(pt)) == pt` | P0 |
| `hex::encode` + `decode` | Round-trip | P1 |
| `pbkdf::format_phc` + `parse_phc` | Round-trip | P1 |
| `ledger::AnchorHash::to_hex` + `from_hex` | Round-trip | P1 |

### CI integration

```yaml
# .github/workflows/formal-verification.yml
on:
  schedule: [{cron: '0 4 * * 1'}]   # Weekly Monday 04:00
  workflow_dispatch:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: rustup toolchain install nightly
      - run: cargo install verus
      - run: verus --crate enprot src/cas.rs src/prot.rs
```

## Implementation plan

1. Audit which functions are in Verus's supported subset.
2. Write `requires`/`ensures` specs for `cas::save`/`load`.
3. Verify locally — fix any counterexamples.
4. Extend to `etree::parse`/`tree_write`.
5. Extend to `prot::encrypt`/`decrypt`.
6. Add weekly CI workflow.
7. Document the verification guarantees in `docs/formal-verification.md`.

## Test plan

- [ ] Verus accepts the specs without counterexamples.
- [ ] Deliberate bugs (e.g., swap bytes in CAS save) are caught by
  Verus.
- [ ] Weekly CI runs to completion without timeout.
- [ ] Documented guarantees are clear to non-formal-methods readers.

## Out of scope

- Full-program verification (the entire crate). Unrealistic effort.
- Verification of FFI code (out of Verus's supported subset).
- Verification of Botan/rnp calls (their code, not ours).
- Model checking (state-space enumeration) — different technique;
  defer.
- Information-flow security (non-interference) — harder; defer.
