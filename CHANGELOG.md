# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **CLI is now subcommand-style**: `enprot encrypt -w WORD file.ept` instead of `enprot -e WORD file.ept`. The flat-flag form is gone. (#22)
- **`-k` no longer splits on commas**: one `WORD=PASSWORD` per flag; use multiple `-k` for multiple pairs. (#19)
- **Rust edition 2024** (minimum Rust 1.85).

### Added

- **Subcommand CLI**: `encrypt`, `decrypt`, `store`, `fetch`, `encrypt-store`, `passthrough`, `verify`, `list`, `completions`. (#22)
- **Deterministic AES-GCM**: `aes-256-gcm-det` and `aes-256-gcm-siv-det` variants derive the nonce from plaintext via HKDF + HMAC, enabling CAS deduplication for encrypted segments. (#39)
- **`--output-dir <DIR>` flag** and `-p DIR/` directory mode for multi-file output. (#18)
- **`--lang <LANG>` flag**: separator presets for `raw`, `c`, `python`, `html`, `latex`. 
- **`enprot verify` subcommand**: check markup structure, CAS pointers, and extfield format without decrypting.
- **`enprot list` subcommand**: list all WORD segments in a file with type and crypto metadata.
- **`enprot completions <SHELL>`**: generate bash/zsh/fish/PowerShell completion scripts.
- **Typed `Error` enum** (`src/error.rs`) with `thiserror`. `app_main` returns `Result<()>`. (#23)
- **Property-based tests** via `proptest`: round-trip + determinism checks for the `-det` variants. (A10)
- **`ParseOps` decomposition**: `Separators`, `Transforms`, `CryptoConfig` inner structs. (A1)
- **`etree/` module split**: `mod.rs`, `parse.rs`, `transform.rs`, `write.rs`, `blob.rs`. (A3)
- **Password module** (`src/password.rs`): TTY-aware reading extracted from `prot.rs`. (A4)
- **NIST policy `AlgKind` enum**: replaces stringly-typed `kind` parameter. (A5)
- **`cipher::format/parse_cipher_extfield`**: single source of truth for the cipher wire format. (A2)
- **`--pbkdf legacy` deprecation warning**: stderr message on encrypt.
- **Pre-commit hook** (`.githooks/pre-commit`): fmt + clippy + typos.
- **`deny.toml`**: cargo-deny config for license + advisory checking.
- **`typos.toml`**: spell-checker config with enprot vocabulary.
- **`SECURITY.md`**: vulnerability reporting policy.
- **`CONTRIBUTING.md`**: development setup and PR process.
- **Dependabot config**: weekly cargo + github-actions dep bumps.
- **Release profile** with LTO + codegen-units=1 + strip.

### Changed

- **Botan 2.13 → Botan 3** (CI builds against 3.7.0; Homebrew 3.12.0). The `botan` crate is at 0.11 with `botan3` + `pkg-config` features.
- **Dropped `block-cipher-trait`** (deprecated). AES-GCM-SIV stays via RustCrypto `aes-gcm-siv` 0.11 (Botan doesn't implement RFC 8452).
- **Dropped `phc` 0.2** (unmaintained). Replaced with a 30-line PHC parser/serializer in `pbkdf.rs` that accepts padded base64 salts.
- **`clap` 2.33 → 4.5** with `Parser` derive.
- **`rpassword` 2 → 7**. TTY-detecting password reader.
- **`phf` 0.8 → 0.14**, `hex` 0.3 → 0.4, `num` dropped.
- **`assert_cmd` 0.11 → 2**, `predicates` 1 → 3, `tempfile` 3.1 → 3.
- **CI**: `actions/checkout@v7`, `dtolnay/rust-toolchain`, `snapcore/action-build/publish`, concurrency cancellation, typos job, cargo-deny + cargo-audit job.
- **Snap**: `core20` → `core22`, `libbotan-2-dev` → `libbotan-3-dev`.
- **Windows static builds**: botan-3 library suffix.

### Fixed

- **#50**: Windows stdin password reading now works via rpassword 7's TTY-aware path.
- **#23**: All `Result<T, &'static str>` replaced with typed `Error` enum. `panic!` calls on max recursion depth replaced with `Err` returns.
- **AES-SIV key length**: Botan 3 reports 64-byte keys for `AES-256/SIV` (RFC 5297 double-key); PBKDF derives `key_len_max()` bytes.

## [0.3.1] - 2020-10-05

- Initial public release.
