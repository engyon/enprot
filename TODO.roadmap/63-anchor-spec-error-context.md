# 63 — Wire format: anchor-v1 spec + error context improvements

**Priority**: P2
**Status**: specified

## Problem

Two documentation and diagnostics gaps:

### 1. Missing anchor wire format spec

The CHAIN directive's extfield schema (parents, signer,
co_signers, sigs, payload, ts, mut) is documented only in code
comments. `docs/schemas/` has `manifest-v1.md`, `conflict-v1.md`,
and `enprot-v1.md` (JSON output) — but no `anchor-v1.md`.

The multi-sig extension (TODO.roadmap/57) added `signers:` /
`sigs:` fields that aren't documented anywhere except in code.

### 2. Error messages lack context

54 `Error::Msg` calls across the codebase produce messages like
"signer fingerprint mismatch" without the file name, WORD, or
line number where the error occurred. Debugging requires
reading the source to find which call site produced the message.

## Solution

### 1. docs/schemas/anchor-v1.md

Document:
- Single-signer fields: `signer`, `sig`, `payload`, `ts`, `mut`, `parents`
- Multi-signer fields: `signers`, `sigs` (TODO.roadmap/57)
- Backwards-compatibility rules
- Extensibility: unknown fields preserved by parsers

### 2. Error context wrapping

Add an `Error::context(self, ctx: &str)` method (or adopt
`anyhow::Context`) that wraps any error with a file/WORD/operation
context. Example:

```rust
// Before:
let fp = KeyFp::from_pem(&pem)?;

// After:
let fp = KeyFp::from_pem(&pem)
    .map_err(|e| e.with_context(format!("loading trust root {}", path.display())))?;
```

This doesn't require a new Error variant — it wraps the existing
message in a richer string. The Display output becomes:
`"loading trust root builder.pem: signer fingerprint mismatch"`.

## Acceptance criteria

- [ ] `docs/schemas/anchor-v1.md` exists and covers all extfields
- [ ] Error messages on the 5 most common failure paths include
      file name and operation context
- [ ] No new Error variants needed (context is a wrapper)
