# A12 — Benchmarks (deferred)

## Problem

No performance benchmarks. Questions like "is `--pbkdf argon2` slower
than `--pbkdf pbkdf2-sha512` at default msec?" have no data behind
them. Performance regressions slip in silently.

## Approach (deferred)

Add a `criterion` benchmark harness in `benches/`:

- `benches/parse.rs` — parse a representative 1k-line EPT file.
- `benches/transform.rs` — passthrough (no-op) and a full
  encrypt-store-fetch round-trip on the same file.
- `benches/pbkdf.rs` — `derive_key` with argon2 / scrypt / pbkdf2
  at default msec.

Each benchmark is ~30 lines. CI doesn't run them by default; they're
invoked manually with `cargo bench` and tracked locally.

## Why deferred

No perf concerns today. The whole pipeline processes a 1k-line file
in well under a second. Adding criterion pulls in another 30+ deps and
~5MB of build artifacts. Worth doing when (a) a perf regression
surfaces, or (b) someone is shopping PBKDF parameter defaults.

When that time comes:

1. `cargo add criterion --dev --features html_reports`
2. `mkdir benches`
3. `[[bench]] name = "parse"` etc. in `Cargo.toml`
4. Run `cargo bench` and inspect `target/criterion/report/index.html`.
