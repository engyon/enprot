# Cargo metadata — small polish

## Problem

`Cargo.toml` is missing standard metadata fields that affect
discoverability and build reproducibility:

- No `rust-version` pin (edition 2024 requires Rust 1.85+; users on
  older toolchains get confusing errors).
- No `documentation` link (docs.rs picks it up automatically but
  advertising it in metadata is the convention).
- No `readme` field (cargo registry shows README.adoc as the
  description but doesn't link it explicitly).
- `categories` and `keywords` are present but could be tighter.

## Approach

```toml
[package]
name        = "enprot"
version     = "0.3.1"
authors     = ["Ribose Inc. <open.source@ribose.com>"]
license     = "BSD-2-Clause"
description = "enprot command line tool for Engyon"
repository  = "https://github.com/engyon/enprot"
homepage    = "https://github.com/engyon/enprot"
documentation = "https://github.com/engyon/enprot/blob/main/README.adoc"
readme      = "README.adoc"
categories  = ["command-line-utilities", "cryptography"]
keywords    = ["encryption", "engyon", "ept", "botan"]
edition     = "2024"
rust-version = "1.85"
autotests   = false
```

`rust-version = "1.85"` is the minimum that supports edition 2024.
cargo will refuse to build on older Rust with a clear error.

## Files

- `Cargo.toml` — add the missing fields.

## Verification

```
cargo build
cargo publish --dry-run   # confirms metadata is well-formed
```
