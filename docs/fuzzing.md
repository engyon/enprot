# Fuzzing

The parser has many branches and state-machine transitions; property
tests cover the common paths but random inputs from `cargo-fuzz`
surface panics on adversarial or pathological inputs.

## Setup

```sh
cargo install cargo-fuzz
```

`cargo-fuzz` requires the nightly toolchain for the sanitizer hooks:

```sh
rustup install nightly
```

## Targets

Two targets live under `fuzz/fuzz_targets/`:

- `parse_no_panic` — feeds random bytes to `enprot::etree::parse`.
  Round-trip identity is NOT asserted (random bytes rarely produce
  identical output); the goal is just to surface panics.
- `conflict_well_formed` — generates well-formed CONFLICT blocks
  with random WORDs and inner content; asserts the parser either
  produces a tree with one Conflict node or returns `Err` — but
  never panics.

## Running

```sh
# Default corpus (no time limit) — runs until interrupted:
cargo +nightly fuzz run parse_no_panic
cargo +nightly fuzz run conflict_well_formed

# With a max-duration cap (CI-style):
cargo +nightly fuzz run parse_no_panic -- -max_total_time=60

# Run the existing corpus only (no new inputs):
cargo +nightly fuzz run parse_no_panic -- -runs=0
```

Corpus and crash artifacts are stored under
`fuzz/corpus/<target>/` and `fuzz/artifacts/<target>/`. Both
directories should be `.gitignore`d (they grow large); the
seed corpus (if any) is committed under
`fuzz/corpus/<target>/seed/`.

## CI integration

Fuzzing is intentionally NOT part of the standard CI pipeline —
each run is expensive (typically minutes per thousand iterations
once libFuzzer has explored the input space). Run the targets
manually before each release; commit any minimized crash inputs as
regression tests under `tests/regression/`.
