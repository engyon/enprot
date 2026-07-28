# 13 — Fuzzing harness in CI

**Priority**: P1
**Status**: done (setup); targets land incrementally

## Problem

enprot's parser is hand-written and line-oriented. `proptest` covers
round-trip + determinism but not malformed input. A single bad input
shouldn't panic the CLI.

The parser is the highest-risk surface:
- Arbitrary user input (text files)
- Multiple host-language separator modes (raw, C, Python, HTML, LaTeX)
- Extfield parsing (`pbkdf:`, `cipher:`, future `attr:`)
- Base64 ciphertext decoding
- Recursive block nesting (max-depth)

## Solution

### Add cargo-fuzz setup

```sh
cargo add --dev cargo-fuzz
cargo fuzz init
```

Creates `fuzz/` directory with `Cargo.toml` + `fuzz_targets/`.

### Fuzz targets

`fuzz/fuzz_targets/parse_round_trip.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use enprot::etree::{parse, ParseOps, tree_write};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut paops = ParseOps::new(enprot::crypto::default_policy()).unwrap();
    let _ = paops.separators;  // use defaults
    if let Ok(tree) = parse(Cursor::new(text.as_bytes()), &mut paops) {
        let mut out = Vec::new();
        let _ = tree_write(&tree, &mut out, &paops);
    }
});
```

`fuzz/fuzz_targets/parse_extfields.rs`:

```rust
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let _ = enprot::etree::parse::parse_encrypted_extfields(&tokens, &fake_paops(), 0, "");
});
```

`fuzz/fuzz_targets/merge_driver.rs`:

```rust
fuzz_target!(|data: &[u8]| {
    // Generate three files (ancestor, ours, theirs) from fuzzer input.
    let (ancestor, ours, theirs) = split_into_three(data);
    let _ = enprot::merge::merge(&ancestor, &ours, &theirs);
});
```

### CI integration

New `.github/workflows/fuzz.yml`:

```yaml
name: fuzz
on:
  schedule:
    - cron: '0 6 * * 1'  # weekly Monday 06:00 UTC
  workflow_dispatch: {}

jobs:
  fuzz-parser:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v7
      - run: ./ci/install.sh
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run parse_round_trip -- -max_total_time=600
      - run: cargo fuzz run parse_extfields -- -max_total_time=300
      - run: cargo fuzz run merge_driver   -- -max_total_time=300
```

Runs weekly. Findings uploaded as artifacts; failures open issues.

### Regression corpus

Checked-in `fuzz/corpus/` directory with seed inputs:

- Valid EPT files (one per host-language separator)
- Edge cases (empty files, deeply nested blocks, malformed base64)
- Inputs that previously crashed (regression tests)

## Acceptance criteria

- [x] `cargo fuzz init` done; `fuzz/` directory exists
- [ ] 3 fuzz targets implemented
- [ ] Weekly CI job runs targets
- [ ] Seed corpus checked in
- [ ] Crash artifacts documented + fixed

## Cross-references

- Confium has `fuzz/` (similar pattern; we can mirror their CI config)
- TODO.roadmap/54 — original fuzzing tracker
- [[12-reproducible-builds]] — companion quality measure
