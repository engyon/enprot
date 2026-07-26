# 54 — Parser fuzz target

**Priority**: P2
**Status**: specified

## Problem

The EPT parser (TODO.roadmap/43 added the CONFLICT/OURS/THEIRS
machinery on top of BEGIN/END/ENCRYPTED) has many branches and
state-machine transitions. Property tests cover the common paths;
random input from `cargo-fuzz` would surface panics on adversarial
or pathological inputs (deeply nested CONFLICT blocks, missing
END keywords, mode-switches in wrong context).

## Solution

Add `fuzz/` directory with cargo-fuzz targets. Initial targets:

- `fuzz/fuzz_targets/parse_round_trip.rs` — generate random bytes,
  parse, re-serialize, assert the parser doesn't panic. Round-trip
  identity is NOT asserted (random bytes rarely produce identical
  output) — the goal is just no panics.
- `fuzz/fuzz_targets/conflict_well_formed.rs` — generate well-formed
  conflict blocks with random keyws and random inner content,
  assert parse + serialize round-trips identically.

CI integration is optional (fuzzing is slow). The targets exist for
manual runs before releases.

## Acceptance criteria

- [ ] `cargo fuzz run parse_round_trip` runs without panics for 1M
      iterations on the dev machine
- [ ] `cargo fuzz run conflict_well_formed` runs without panics for
      1M iterations
- [ ] Documented in `docs/benches/README.md` (the existing perf doc)
      or a new `docs/fuzzing.md`
