# 02 — Rust edition 2024 and cleanup

## Goal

Move from edition 2015 (implicit, never set) to edition 2024. Remove all
`extern crate` declarations (dead since 2018). Run rustfmt to settle formatting.

## Files

- `Cargo.toml` — add `edition = "2024"`
- `src/lib.rs`, `src/cipher.rs`, `tests/tests.rs` — remove `extern crate`
- All `src/*.rs` — `cargo fmt`

## Approach

1. Add `edition = "2024"` to `[package]` in `Cargo.toml`.
2. Delete the `extern crate {aes, aes_gcm_siv, block_cipher_trait, botan,
   clap, hex, num, phc, phf, rpassword}` block at the top of `src/lib.rs`.
3. Delete the `extern crate {assert_cmd, cpu_time, predicates, tempfile}`
   block in `tests/tests.rs`.
4. Delete `extern crate tempfile` in the `#[cfg(test)] mod tests` block of
   `src/etree.rs`.
5. Delete `extern crate aes` in `src/cipher.rs` (only present after we remove
   the hand-rolled cipher in phase 05; do that there).
6. Run `cargo fmt --all` to normalize.

### Edition 2024 caveats worth verifying

- `gen` keyword reserved — not used in this crate.
- `unsafe_op_in_unsafe_fn` lint promoted to deny — none here (no `unsafe`).
- `TailExpr` drop order in 2024 — audit by running `cargo test`.

## Verification

```
cargo check --all-targets
cargo test
```

Both should pass.

## Rollback

Drop the `edition` field; `extern crate` lines are git-recoverable.
