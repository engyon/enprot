# 36 — Fuzz targets for parser + transform

**Priority**: P2
**Status**: specified

## Problem

Property tests (`tests/proptest_*`) cover common cases with 256
random inputs each. They miss:

- Adversarial inputs crafted to trigger edge cases (deeply nested
  blocks, malformed UTF-8, pathologically long lines).
- Integer overflow in line counting / offset arithmetic.
- Stack overflow from unbounded nesting depth.
- PANIC vs ERROR distinction — proptest asserts on properties;
  fuzz targets assert "doesn't panic" + "no undefined behavior".

A fuzz target runs indefinitely, exploring the input space via
coverage-guided mutation. It finds bugs property tests can't reach.

## Goals

- `fuzz/` workspace member with one fuzz target per public API surface.
- Each target runs for ≥1M executions in CI on a weekly schedule.
- Corpus is committed for regression coverage.
- Crash reproductions are auto-minimized and reported as issues.

## Design

### Targets

| Target | Harness | What it exercises |
|---|---|---|
| `fuzz_parse` | `etree::parse(reader, paops)` | Parser robustness on arbitrary bytes |
| `fuzz_transform` | `parse → transform → write` round-trip | Full pipeline doesn't panic |
| `fuzz_cas_load` | `cas::load(hash, paops)` with random hash strings | Hash validation |
| `fuzz_phc_parse` | `pbkdf::parse_phc(s)` | PHC string parser |
| `fuzz_extfield_decode` | `ledger::SignedAnchor::from_extfields(map)` | Extfield → anchor |
| `fuzz_separators` | parser with random `left`/`right` separators | Non-default separator robustness |

### Structure

```
fuzz/
├── Cargo.toml                  # workspace member, depends on enprot + libfuzzer-sys
├── fuzz_targets/
│   ├── fuzz_parse.rs
│   ├── fuzz_transform.rs
│   ├── fuzz_cas_load.rs
│   ├── fuzz_phc_parse.rs
│   ├── fuzz_extfield_decode.rs
│   └── fuzz_separators.rs
├── corpus/
│   ├── fuzz_parse/
│   │   ├── 01-basic.ept
│   │   ├── 02-encrypted.ept
│   │   └── ...
│   └── fuzz_transform/
│       └── ...
└── README.md
```

### Target shape

```rust
// fuzz/fuzz_targets/fuzz_parse.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut paops = match enprot::etree::ParseOps::new(
        Box::new(enprot::crypto::CryptoPolicyDefault {})
    ) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops.runtime.fname = "<fuzz>".into();
    let cursor = Cursor::new(data.to_vec());
    // Must not panic. Errors are fine — we're testing robustness,
    // not correctness.
    let _ = enprot::etree::parse(cursor, &mut paops);
});
```

### CI integration

- **On every PR**: run each fuzz target for 60 seconds (smoke check).
- **Weekly cron**: run each target for 30 minutes, upload corpus
  diffs as artifacts, file issues for crashes.
- **Corpus commits**: when the weekly run finds new coverage, commit
  the new corpus entries to `fuzz/corpus/<target>/`.

## Implementation plan

1. Add `fuzz/` directory with `Cargo.toml` (workspace member).
2. Add `libfuzzer-sys` as a dev-dependency.
3. Implement the 6 initial targets.
4. Seed each corpus with 3-5 known-good EPT files.
5. Add a CI workflow (`.github/workflows/fuzz.yml`) with the smoke
   + weekly split.
6. Document in `fuzz/README.md` how to run locally:
   `cargo +nightly fuzz run fuzz_parse`.

## Test plan

- [ ] Each target runs for 60 seconds without crashing on empty input.
- [ ] Each target finds at least one "interesting" input in 5 minutes
  (coverage-guided exploration working).
- [ ] Known bugs surfaced by fuzzing are filed as issues with a
  minimised reproduction.

## Out of scope

- Fuzzing the crypto primitives — covered by Botan's own fuzzing.
- Differential fuzzing against a reference implementation (none exists).
- WASM-based in-browser fuzzing (separate TODO).
