# 26 — Typed errors: finish the callsite migration

**Priority**: P0
**Status**: specified

## Problem

`TODO.complete/02-typed-errors` shipped the typed `Error` enum (every
variant has structured fields: `Parse { file, lineno, msg }`,
`Cas(String)`, `Cipher(String)`, etc.) and migrated the FFI
classifier. The migration of *callsites* stopped at roughly the
halfway mark:

```
$ grep -rc 'Error::msg\|Error::Msg' src/ enprot-ffi/src/ | \
    awk -F: '{sum += $2} END {print sum}'
106
```

Distribution (post-#236 cli.rs decomposition):

| File                   | Count | Notes |
|------------------------|-------|-------|
| `src/cli/mod.rs`       | ~28   | CLI dispatch — IO path opens, arg-validation, word-password lookups |
| `src/ledger/anchor.rs` | ~17   | Anchor parsing — extfield decode, signature verify, parent resolution |
| `src/etree/transform.rs` | ~6  | "No data in ENCRYPTED" + similar block-shape errors |
| `src/resolve/mod.rs`   | ~5   | CONFLICT-block resolver errors |
| `src/provenance/mod.rs`| ~2   | Manifest walker errors |
| `src/cli/init.rs`      | ~3   | Config-template write errors |
| `src/cli/merge_cmd.rs` | ~1   | Merge-driver errors |
| `enprot-ffi/src/lib.rs`| ~2   | FFI marshalling |
| Other (one-offs)       | ~42  | Spread across small modules |

Every `Error::msg(format!(...))` site loses three things:

1. **Machine-readable kind** — FFI callers must string-match.
2. **Structured context** — paths, operations, hashes are baked into the message string.
3. **Stable Display contract** — refactoring a message breaks tests that substring-match.

## Goals

- **Zero `Error::Msg` callsites in `src/`** (CI gate via `grep -rE 'Error::msg\b|Error::Msg\b' src/`).
- Every typed variant has at least one unit test asserting `to_string()` output is stable.
- FFI classifier updated to dispatch exhaustively on the new variants.
- Existing tests still pass — no Display format break unless the old format was wrong.

## Design

### Migration is mechanical, not architectural

The typed variants already exist. The migration is per-callsite: read
the surrounding context, pick the matching variant, replace the
`format!` with structured fields.

Decision tree (apply top-down at each callsite):

```
Is the error from a std::io::Error?             → Error::Io (via `?` if `From` is in scope)
Else, is it about an algorithm/policy choice?   → Error::Policy("...")
Else, is it a CAS blob load/save?               → Error::Cas("...")
Else, is it a cipher creation/decrypt failure?  → Error::Cipher("...")
Else, is it a PBKDF derivation failure?         → Error::Pbkdf("...")
Else, is it a JSON serialization failure?       → Error::Json("...")
Else, is it a parse error with line info?       → Error::Parse { file, lineno, msg }
Else, is it a capability-policy rule?           → Error::PolicyViolation { rule, context }
Else, is it a PHC-string parse failure?          → Error::Phc("...")
Else, is it a hex/base64 decode failure?        → Error::Hex(...) / Error::Base64(...)
Else, is it a botan FFI failure?                → Error::Botan(...) (via Error::botan)
Else                                            → Error::Msg("...") [last resort]
```

The last-resort branch should be empty by end of migration. If a
new variant is needed, add it (the enum is intentionally open for
extension per OCP).

### Per-module order

1. `src/ledger/anchor.rs` — 17 sites, all extfield/signature errors. Many become `Error::Extfield { field, reason }` (need to add the variant) or `Error::SignatureVerify { key_id }`.
2. `src/cli/mod.rs` — 28 sites, mostly IO and arg-validation. `Error::Io` via `?`, `Error::InvalidArg` for arg-validation (need to add).
3. `src/etree/transform.rs` — 6 sites, block-shape errors. Add `Error::BlockShape { word, reason }`.
4. `src/resolve/mod.rs` — 5 sites. Add `Error::ConflictResolve { word, reason }`.
5. One-off sweeps through smaller modules.

Each module = 1 commit. Total: 5–7 commits.

### New variants to add

```rust
// In src/error.rs, add:
#[error("invalid argument {arg}: {reason}")]
InvalidArg { arg: &'static str, reason: String },

#[error("extfield {field} malformed: {reason}")]
Extfield { field: &'static str, reason: String },

#[error("signature verification failed for {key_id}")]
SignatureVerify { key_id: String },

#[error("block {word} shape error: {reason}")]
BlockShape { word: String, reason: String },

#[error("conflict resolution failed for {word}: {reason}")]
ConflictResolve { word: String, reason: String },
```

### FFI classifier update

```rust
// enprot-ffi/src/lib.rs::classify_error
fn classify_error(err: enprot::Error) -> EnprotResult {
    use enprot::Error::*;
    let (code, msg) = match err {
        Io(_) | Cas(_) => (ENPROT_ERR_IO, err.to_string()),
        Parse { .. } | Extfield { .. } | BlockShape { .. } | Phc(_) =>
            (ENPROT_ERR_PARSE, err.to_string()),
        Botan(_) | Cipher(_) | Pbkdf(_) | SignatureVerify { .. } =>
            (ENPROT_ERR_CRYPTO, err.to_string()),
        Policy(_) | PolicyViolation { .. } =>
            (ENPROT_ERR_POLICY, err.to_string()),
        Hex(_) | Base64(_) | Json(_) =>
            (ENPROT_ERR_FORMAT, err.to_string()),
        InvalidArg { .. } | ConflictResolve { .. } =>
            (ENPROT_ERR_INVALID, err.to_string()),
        Msg(_) => (ENPROT_ERR_UNKNOWN, err.to_string()),
    };
    EnprotResult::err(code, &msg)
}
```

## Implementation plan

Each step is its own commit on a single PR:

1. Add the 5 new variants to `src/error.rs`. Unit-test Display output for each.
2. Migrate `src/ledger/anchor.rs` (17 sites → typed).
3. Migrate `src/cli/mod.rs` (28 sites).
4. Migrate `src/etree/transform.rs` (6 sites).
5. Migrate `src/resolve/mod.rs` (5 sites).
6. Sweep remaining files (provenance, init, merge_cmd, ffi, one-offs).
7. Add CI gate: `grep -rE 'Error::msg\b|Error::Msg\b' src/ | grep -v 'error.rs'` must be empty.
8. Update FFI classifier to exhaustive match.

## Test plan

- [ ] All existing tests still pass (no Display regression).
- [ ] New tests for each new variant's Display output.
- [ ] `cargo clippy -- -D warnings` clean.
- [ ] CI grep gate passes.
- [ ] FFI classifier is `#[deny(unreachable_patterns)]`-safe.

## Out of scope

- Localization (i18n) — separate TODO.
- Error-code stability guarantees for the FFI surface — arrives when
  the FFI itself hits 1.0.
- Structured error logging via tracing — TODO.complete/09.
