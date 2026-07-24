# 05 — Botan 3 migration and cipher consolidation

## Goal

Bump the `botan` crate from 0.6.0 to 0.11+. Use Botan 3 for every cipher
Botan actually implements. Drop the RustCrypto `block-cipher-trait`
dependency that the old hand-rolled impl needed.

## Pivot from the original plan

Original plan: also drop `aes-gcm-siv` because "Botan 3 supports GCM-SIV
natively." **This is wrong.** Verified against Botan 3.12 source:
`src/lib/modes/aead/` has no `gcm_siv` directory. Botan does not implement
RFC 8452 AES-GCM-SIV in any version (checked release notes through 3.12,
May 2026). There is no `gcm_siv` module to enable.

Final design: two cipher backends behind one `SymmetricCipher` trait.
- `BotanCipher` — `aes-256-siv`, `aes-256-gcm` via Botan.
- `AesGcmSivCipher` — `aes-256-gcm-siv` via RustCrypto `aes-gcm-siv = "0.11"`.

Dispatch happens in `encryption(alg)` / `decryption(alg)`.

## Files

- `Cargo.toml`
- `ci/botan-modules` (no change — `gcm_siv` was never a Botan module)
- `src/cipher.rs` — two-backend trait dispatch
- `src/crypto.rs` — botan 0.11 API adjustments
- `src/pbkdf.rs` — botan 0.11 RNG mutability
- `src/etree.rs` — `ParseOps::new` RNG construction
- `src/prot.rs` — RNG mutability
- `src/utils.rs` — botan 0.11 base64 (unchanged surface)

## Local environment

Botan 3.12 from Homebrew provides `AES-256/GCM` and `AES-256/SIV`. AES-GCM-SIV
is provided by the RustCrypto `aes-gcm-siv` crate, which is pure Rust and
compiles on every target without system deps.

## botan 0.11 API deltas applied

| Surface | 0.6 | 0.11 | Action |
|---------|-----|------|--------|
| `RandomNumberGenerator::new()` | no args | no args (kept) | unchanged |
| `HashFunction::update` / `finish` | `&self` | `&mut self` | bind `let mut hash` |
| `Cipher::set_key` / `set_associated_data` / `process` | `&self` | `&mut self` | trait method `process(&mut self, …)` |
| `RandomNumberGenerator::read` | `&self` | `&mut self` | thread `&mut Option<RNG>` through pbkdf/prot |
| `derive_key_from_password(_timed)` | unchanged | unchanged | none |
| `base64_encode` / `base64_decode` | unchanged | unchanged | none |

## Verification

```
cargo check
cargo test cipher            # KAT tests in cipher.rs (aes-256-gcm, aes-256-gcm-siv)
cargo test                   # full suite — 64/64 pass locally
cargo clippy --all-targets -- -D warnings   # clean
```

All `test-data/*.ept` golden files round-trip identically.

## Rollback

Restore `src/cipher.rs`, revert `Cargo.toml`.
