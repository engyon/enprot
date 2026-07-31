# 02 — Typed errors

**Priority**: P0
**Status**: specified

## Problem

`src/error.rs` defines:

```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Botan(#[from] botan::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}
```

`Error::Msg(String)` is the catch-all. Roughly **47%** of error-producing sites in `src/` construct an `Error::Msg` with a hand-formatted message. Consequences:

- **No machine-readable error kind.** Callers (including the FFI in [01-ffi-pipeline-execution]) cannot dispatch on cause — they have to string-match. Brittle, slow, and impossible to localize.
- **Lossy provenance.** A "failed to open X" error doesn't carry the path, the OS error, or the operation (read vs. write). It's just a string.
- **Duplicate formatting logic.** Every callsite writes `format!("failed to open {}: {}", path, e)` by hand.
- **Test brittleness.** Property tests and integration tests assert on substrings of error messages. Refactoring a message breaks the test without changing behavior.

## Goals

- Every error variant carries typed context (paths, operations, line numbers, kinds).
- FFI error mapping is exhaustive: `match` on `Error` returns a specific `ENPROT_ERR_*` code.
- Display output stays human-readable; Debug output includes structured fields.
- No new format-string duplication — `thiserror::Error`'s `#[error]` does the work.

## Design

### The new enum

```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    // I/O
    #[error("failed to open {path} for {op}")]
    OpenFile { op: FileOp, path: PathBuf, #[source] source: std::io::Error },

    #[error("failed to read {path}: {source}")]
    ReadFile { path: PathBuf, #[source] source: std::io::Error },

    #[error("failed to write {path}: {source}")]
    WriteFile { path: PathBuf, #[source] source: std::io::Error },

    #[error("CAS error: {op} blob {hash} at {dir}")]
    Cas { op: CasOp, hash: String, dir: PathBuf, #[source] source: Box<Error> },

    // Parse
    #[error("parse error at {path}:{line}: {kind}")]
    Parse { path: String, line: usize, kind: ParseErrorKind },

    #[error("wire-format extfield {field} is malformed: {reason}")]
    Extfield { field: &'static str, reason: String },

    // Crypto
    #[error("botan {op} failed")]
    BotanOp { op: &'static str, #[source] source: botan::Error },

    #[error("cipher {alg} rejected by policy")]
    CipherRejectedByPolicy { alg: String },

    #[error("PBKDF {alg} rejected by policy")]
    PbkdfRejectedByPolicy { alg: String },

    #[error("hash {alg} rejected by policy")]
    HashRejectedByPolicy { alg: String },

    // Signature / PKI
    #[error("signature verification failed for {key_id}")]
    SignatureVerify { key_id: String },

    #[error("recipient key rejected: {reason}")]
    RecipientKey { reason: String },

    // CLI
    #[error("invalid argument {arg}: {reason}")]
    InvalidArg { arg: &'static str, reason: String },

    // Generic — to be phased out
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy)]
pub enum FileOp { Read, Write, Append }

#[derive(Debug, Clone, Copy)]
pub enum CasOp { Save, Load, List }

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ParseErrorKind {
    #[error("unterminated block")]
    UnterminatedBlock,
    #[error("unexpected directive {0}")]
    UnexpectedDirective(&'static str),
    #[error("invalid base64 in DATA line")]
    InvalidBase64,
    #[error("missing WORD in directive")]
    MissingWord,
    #[error("mismatched END {0} (expected {1})")]
    MismatchedEnd(String, String),
}
```

### Migration strategy

Mechanical refactor — one module at a time, in this order:

1. `src/error.rs` — define the new enum alongside the old; keep `Msg(String)` as `Other(String)`.
2. `src/etree/` — parser is the biggest user of `Error::Msg`. Replace with `Error::Parse`.
3. `src/cas.rs`, `src/prot.rs`, `src/cipher.rs` — crypto paths.
4. `src/cli.rs` — argument handling.
5. `src/pki.rs` — PKI signature paths.
6. Final sweep: `Other(String)` becomes empty; remove it.

Each module's migration is a separate commit on a single PR.

### FFI mapping

In `enprot-ffi/src/lib.rs::classify_error`:

```rust
fn classify_error(err: enprot::Error) -> EnprotResult {
    use enprot::Error::*;
    let (code, msg) = match err {
        OpenFile { .. } | ReadFile { .. } | WriteFile { .. } | Cas { .. }
            => (ENPROT_ERR_IO, err.to_string()),
        Parse { .. } | Extfield { .. }
            => (ENPROT_ERR_PARSE, err.to_string()),
        BotanOp { .. } | CipherRejectedByPolicy { .. } | PbkdfRejectedByPolicy { .. }
        | HashRejectedByPolicy { .. } | SignatureVerify { .. } | RecipientKey { .. }
            => (ENPROT_ERR_CRYPTO, err.to_string()),
        InvalidArg { .. } | Other(_)
            => (ENPROT_ERR_INVALID, err.to_string()),
    };
    EnprotResult::err(code, &msg)
}
```

### Testing

Each typed variant gets a unit test asserting `to_string()` output is stable (the display strings become a public contract for users who grep on error messages).

Property test: every `Error` variant round-trips through `format!("{err}") → Error::from_str` (where applicable). Not all variants can — only the ones whose Display is unambiguous.

## Implementation plan

1. Introduce new enum (commit 1).
2. Migrate `etree/` (commit 2).
3. Migrate crypto modules (commit 3).
4. Migrate CLI + PKI (commit 4).
5. Remove `Other(String)` (commit 5).
6. Update FFI classifier (commit 6, gated on [01-ffi-pipeline-execution]).

## Test plan

- [ ] All existing tests still pass after migration.
- [ ] New tests for each variant's Display output.
- [ ] `cargo clippy -- -D warnings` clean.
- [ ] No `Error::Msg(String)` sites remain (CI gate via grep).

## Out of scope

- Localization (i18n) of error messages — separate TODO.
- Structured error logging — [09-observability-tracing].
- Error-code stability guarantees — first cut is internal; a stable FFI error code space arrives when [01-ffi-pipeline-execution] stabilizes.
