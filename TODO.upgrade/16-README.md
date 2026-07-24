# Remaining audit work, July 2026

This directory now also carries the audit backlog (originally
`TODO.audit/`). The numbered files below are the open items after
issues #23-50 were closed and audit findings A2-A9, A13 landed.

| # | File | Status | Effort |
|---|------|--------|--------|
| 16 | `16-a1-parseops-decomposition.md` | do this round | large |
| 17 | `17-a6-cipher-registry.md`        | deferred      | small (low value) |
| 18 | `18-a10-proptest-roundtrip.md`    | do this round | medium |
| 19 | `19-a11-readme-doctest.md`        | deferred      | medium (low value) |
| 20 | `20-a12-benchmarks.md`            | deferred      | medium |
| 21 | `21-cargo-metadata.md`            | do this round | small |
| 22 | `22-dependabot.md`                | do this round | small |

The "do this round" items land in dedicated PRs (one per item, per
the user's earlier "incremental PR" instruction). The deferred items
stay documented for future contributors.

## Ruby-specific anti-patterns (don't translate to Rust)

The user's prompt included the Ruby-style global CLAUDE.md rules
about `send`, `instance_variable_set/get`, `respond_to?`,
`require_relative`, and `autoload`. None of those have Rust analogs:

- Rust privacy is enforced at compile time; there's no `send` to
  bypass it.
- Rust has no `instance_variable_set/get`. Field access is statically
  checked.
- Rust has no `respond_to?`; types are resolved at compile time.
- Rust has no `require_relative`. Modules are declared via `mod` in
  the parent file, which is the Rust equivalent of Ruby autoload.

The spirit (encapsulation, type safety, MECE module boundaries) is
respected throughout the codebase: every module owns its own state,
`pub` surface is narrow, trait dispatch (`CryptoPolicy`,
`SymmetricCipher`) replaces runtime type checks.

## Architecture wins landed since the upgrade

Recent audit-driven improvements:

- `src/etree/` is now a directory with `mod.rs`, `parse.rs`,
  `transform.rs`, `write.rs`, `blob.rs`. The 828-line `etree.rs` is
  gone (PR #72).
- `src/password.rs` extracts interactive I/O from `src/prot.rs`
  (PR #68).
- NIST policy uses an `AlgKind` enum instead of a stringly-typed
  `kind: &str` parameter (PR #69).
- `cipher::format_cipher_extfield`/`parse_cipher_extfield`/`DEFAULT_CIPHER_ALG`
  own the cipher wire format; `prot.rs` uses the typed helpers (PR #71).
- `parse_encrypted_extfields` threads `paops`/`lineno`/`line` so
  duplicate-extfield errors carry their context (PR #70).
- `app_main` returns `Result<()>`; `ParseOps::new` returns
  `Result<Self>` (PR #67).

Findings A1 (ParseOps decomposition), A10 (proptest), A11 (README
doctest), A12 (benchmarks), and A6 (cipher registry) are the
remaining items.
