# 14 — Warn on `legacy` PBKDF

## Goal

The `legacy` PBKDF mode (plain SHA3-512 truncation, no salt, no iterations)
is kept for backward compatibility with very old enprot blobs. It is
cryptographically weak — trivially brute-forceable, no salting, no work
factor. New encryption should never pick it.

Emit a one-shot warning to stderr when the user explicitly selects it for
encryption (via `--pbkdf legacy`). Decryption of legacy blobs stays
silent — that's the legitimate use case.

## Files

- `src/pbkdf.rs` — add the warning at the top of `pbkdf_legacy`
- `src/prot.rs` — alternative: warn at `encrypt()` when `opts.alg == "legacy"`

## Approach

Warn at `encrypt()` (in `prot.rs`), not at the KDF call site. Reason: the
KDF is invoked for both encryption and decryption; only encryption with
`legacy` is the dangerous case to flag. Decrypting an old legacy blob is
expected and shouldn't warn.

```rust
pub fn encrypt(...) -> Result<...> {
    if pbkdfopts.alg == "legacy" {
        eprintln!(
            "Warning: --pbkdf legacy uses an unsalted SHA3-512 truncation \
             and is retained only for decrypting old blobs. Use argon2, \
             scrypt, or pbkdf2-sha{256,512} for new encryption."
        );
    }
    // ...
}
```

One warning per `enprot` invocation is fine; repeated encryptions within
the same invocation (multi-file) would print it once per file, which is
acceptable for a CLI tool.

## Verification

- `cargo test` — existing tests that use `--pbkdf legacy` will now print
  the warning to stderr. Update the affected tests if any assert on
  empty stderr.
- Manual: `enprot sample/test.ept -e Agent_007 --pbkdf legacy -k Agent_007=x`
  prints the warning.

## Rollback

Drop the conditional.
