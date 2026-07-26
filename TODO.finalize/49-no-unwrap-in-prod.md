# 49 — Eliminate production unwrap/expect

**Priority**: P2
**Status**: done

## Problem

Production code (not test code) contains unwraps that mask real
failure modes:

- `src/pbkdf.rs:164` — `rng.as_mut().unwrap()` panics if
  `CryptoConfig.rng` is `None`.
- `src/pbkdf.rs:188,206` — `opts.params.as_ref().unwrap()`
  assumes the manual-params branch was populated.
- `src/password.rs:43,46` — `expect("password read failure")`
  panics on TTY read errors instead of returning an `Error`.

These are reachable from the CLI on real inputs.

## Solution

- Replace `rng.as_mut().unwrap()` with `Option::ok_or_else(|| Error::msg(...))`.
- Replace `opts.params.unwrap()` with proper branch handling or
  an explicit error.
- Replace `password.rs` `expect()` with `map_err(Error::from)`.

## Acceptance criteria

- [x] No `.unwrap()` or `.expect()` in `src/` outside `#[cfg(test)]`
      (verified via `grep -rn '\.unwrap()\|\.expect(' src/ | grep -v test`)
- [x] All previously-panicking paths return `Result`
- [x] `cargo test` passes
