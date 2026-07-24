# 15 — Rustdoc on the public API

## Goal

The crate exposes a small public API surface (`crypto`, `utils`, `Error`,
`Result`, `app_main`). None of it has rustdoc. Add concise docs so an
external caller (or a future Claude instance) can read the contract
without spelunking through the source.

## Files

- `src/lib.rs` — module-level doc, `app_main` doc
- `src/crypto.rs` — `digest`, `hexdigest`, `CryptoPolicy` trait
- `src/utils.rs` — `base64_encode`, `base64_decode`
- `src/error.rs` — `Error` enum variants, `Result` alias

## Approach

- Module-level `//!` doc on `lib.rs` describing what enprot is and the
  parse → transform → write pipeline.
- Per-function `///` docs on public items. One to three lines each; don't
  restate the type signature.
- Document the `Error` variants with the conditions that produce them.
- No `# Examples` blocks beyond what's already in tests; the integration
  tests serve as examples.

## Verification

`cargo doc --no-deps --all-features` builds cleanly with no warnings.

## Rollback

Remove the doc comments.
