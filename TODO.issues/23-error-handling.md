# 23 — Improve error handling

## Status: resolved by PR #57

The issue asked for:

> our own error type instead of using `&'static str`

and noted `panic!` calls that should be graceful errors.

PR #57 introduced `src/error.rs` with a `thiserror::Error` enum and a
`Result<T>` alias. Every `Result<T, &'static str>` in the crate was
migrated. Concrete variants: `Io`, `Botan`, `Hex`, `Base64`, `Cipher`,
`Pbkdf`, `Policy`, `Parse { file, lineno, msg }`, `Cas`, `Phc`, `Msg`.

PR #58 added rustdoc on every variant.

The `panic!("Maximum recursion depth!")` calls in `etree::transform` and
`etree::parse` were converted to `Err(Error::Msg(...))` returns.

## Action

Comment on the issue with the PR references (`998206a`, `6a40b75`) and
close.

No code change in this triage.
