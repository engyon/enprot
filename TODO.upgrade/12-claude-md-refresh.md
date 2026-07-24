# 12 — CLAUDE.md architecture refresh

## Goal

`CLAUDE.md` (written before the upgrade merge) describes the pre-Botan-3
architecture: hand-rolled `AESGCMSIVCipher`, `&Box<dyn CryptoPolicy>`,
the per-line `cmd_parsers` HashMap, `Result<T, &'static str>` everywhere.
Update so future Claude instances read the current state.

## Files

- `CLAUDE.md`

## Approach

- Replace the cipher-section description with the dual-backend trait
  dispatch (`BotanCipher` + `AesGcmSivCipher`).
- Note `crypto::CryptoPolicy::check_cipher_alg` as the early-reject path.
- Update ParseOps description: typed `Result`, `&dyn CryptoPolicy`, the
  `Command` enum dispatch in `parse()`.
- Note the new `src/error.rs` typed Error and the `Result<T>` alias.
- Update CI section: Botan 3.7 in CI (3.12 local via Homebrew),
  `actions/checkout@v7`, `dtolnay/rust-toolchain`, clippy gate.
- Note the `botan` crate features `botan3` + `pkg-config` are required.

## Verification

Read the file top to bottom — every claim about the code should match
the current source.

## Rollback

Revert the file.
