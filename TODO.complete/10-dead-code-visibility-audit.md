# 10 — Dead code + module-visibility audit

**Priority**: P2
**Status**: specified

## Problem

`src/pki.rs`, `src/cli.rs`, `src/etree/mod.rs` expose many `pub` items that are only used internally. This widens the public API surface, slows compilation (downstream recompiles), and makes future refactors harder.

`cargo +nightly udeps` (cargo-udeps) reports ~15 unused items across the crate.

## Goals

- Every `pub` item in `src/` is reachable by an external consumer (the CLI binary, the FFI crate, or downstream library users via `enprot::*`).
- Everything else is `pub(crate)` or private.
- `cargo +nightly udeps --all-targets` finds zero unused items.
- The library API is documented in `docs/library-api.md` with a stability tier (stable / unstable / internal).

## Implementation plan

1. Run `cargo +nightly udeps`; remove or `pub(crate)`-gate dead items.
2. Audit each `pub mod` in `src/lib.rs`; downgrade if unused externally.
3. Add `#[doc(hidden)]` to items that must stay `pub` for technical reasons (e.g., trait impls) but aren't API.
4. Generate stable-API doc: `cargo doc --features docsrs` → `docs/library-api/index.html`.

## Test plan

- [ ] `cargo +nightly udeps` clean.
- [ ] Semver-check (via `cargo-semver-checks`) shows no breakage if items removed were `pub`.
- [ ] `cargo public-api` diff against last release is intentional.

## Out of scope

- Re-export stable-API items at crate root (separate cleanup).
- Hide everything behind `#[non_exhaustive]` (different concern).
