# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.7](https://github.com/engyon/enprot/compare/v0.5.6...v0.5.7) - 2026-07-29

### Fixed

- *(deploy)* fail-fast: false so native builds survive Docker failures

## [0.5.6](https://github.com/engyon/enprot/compare/v0.5.5...v0.5.6) - 2026-07-29

### Fixed

- *(deploy)* use pwsh shell for Windows + publish partial releases

## [0.5.5](https://github.com/engyon/enprot/compare/v0.5.4...v0.5.5) - 2026-07-29

### Fixed

- *(deploy)* correct Windows PREFIX path construction

## [0.5.4](https://github.com/engyon/enprot/compare/v0.5.3...v0.5.4) - 2026-07-29

### Fixed

- *(deploy)* correct Docker FROM tag + snap version variable + snap deps

## [0.5.3](https://github.com/engyon/enprot/compare/v0.5.2...v0.5.3) - 2026-07-29

### Other

- use prebuilt static musl binary instead of building from source

## [0.5.2](https://github.com/engyon/enprot/compare/v0.5.1...v0.5.2) - 2026-07-29

### Other

- switch base from core22 to core24
- append to .cargo/config.toml instead of overwriting .cargo/config
- *(deploy)* run sed BEFORE snapcore/action-build step in snap job
- *(deploy)* pass BOTAN_VERSION + PREFIX to generate-extras install.sh

## [0.5.1](https://github.com/engyon/enprot/compare/v0.5.0...v0.5.1) - 2026-07-29

### Fixed

- *(deploy)* accept v-prefixed tags from release-plz

### Other

- update CLAUDE.md release section to reflect release-plz flow
- *(deploy)* add workflow_dispatch + unified DEPLOY_TAG for both triggers
- derive CMAKE_SYSTEM_PROCESSOR from TARGET triple in cross-deps script
- Release pipeline gap analysis: fix deploy CI, add LICENSE, aarch64, docs
- document DYLD_LIBRARY_PATH requirement for macOS test runs
- document Windows MSVC support in README installation section
- update CLAUDE.md with Windows MSVC build pipeline
- build zlib static so the test binary has no zlib1.dll dep
- set RUSTFLAGS so botan-sys resolves botan-3.lib globally
- split botan dep per target (drop pkg-config on MSVC)
- use build.rs for link directives (not cargo rustflags which breaks deps)
- use rustflags for linking (cargo config doesn't support rustc-link-lib key)
- fix .cargo/config format (flat target section, not per-lib subtables)
- link all deps (json-c, sexpp, bzip2, zlib) in cargo config
- clear Error stream + global LASTEXITCODE after tolerated cmake install
- reset LASTEXITCODE after tolerated cmake install error
- tolerate cmake install error (rnp.exe not built is OK)
- manually copy rnp headers + lib instead of cmake install
- use full cmake install (component names don't match rnp's)
- use tronkko/dirent for real POSIX dir API on MSVC
- put getopt.h stub in PREFIX/include so compiler finds it
- provide stub getopt.lib for cmake find_library
- GitHub mirrors for deps, stub POSIX headers, build only librnp target
- provide dirent.h + getopt.h from rnp src/common for MSVC
- also build zlib from source for librnp find_package(ZLIB REQUIRED)
- build bzip2 from source for librnp CMake find_package
- Windows install: provide bzip2 dev for librnp CMake find_package
- Windows install: disable bzip2/zlib compression in librnp build
- Restore Windows CI: build botan + json-c + librnp from source

## [0.5.0](https://github.com/engyon/enprot/compare/v0.4.2...v0.5.0) - 2026-07-28

### Other

- Restore deny.toml; fix .gitignore to only match 64-char CAS hashes
- Fix provenance CAS: use set_local_casdir after trait refactor
- Restore deny.toml
- Fix clippy: use .. instead of name: _ in KEY/CERT match patterns
- strategic positioning + RSD spec directive documentation
- Remove stray CAS test blobs + add to .gitignore
- Add IMMUTABLE/MUTED hash verification to enprot verify
- Restore deny.toml (accidentally deleted)
- Implement RSD spec directives: IMMUTABLE/MUTABLE/MUTED + KEY/CERT/UNKEY/UNCERT
- Implementation batch: 7 TODOs landed as code + 4 as docs

## [0.4.2](https://github.com/engyon/enprot/compare/v0.4.1...v0.4.2) - 2026-07-27

### Other

- Bump rnp-rs 0.1.6 -> 0.1.7
- Cross-ref upstream OHOS-blocker issues in TODO.finalize/51
- Document OHOS + rnp-rs blocker (librnp cross-compile pending)
- Update Confium integration tracker to reflect released v0.3.0 crates
- Fix clippy::collapsible_if across cli.rs, config.rs, policy/nist.rs
- Drop Windows from CI matrix (librnp unavailable); tracked in TODO 52
- Bump MSRV 1.85 -> 1.88 (rnp-rs uses let-chains)
- force /usr/local on macOS (SIP blocks /usr)
- Disable ENABLE_PQC/ENABLE_CRYPTO_REFRESH in librnp build
- Fix botan module names (auto_seeding_rng etc. don't exist)
- Expand ci/botan-modules with everything librnp needs
- Fix librnp build: init submodules, build botan first
- Build librnp from source in CI (rnp-rs 0.1.6 needs newest FFI)
- install librnp-dev / rnp for rnp-rs build
- Add OpenPGP signature support via rnp-rs 0.1.6 (required dep)
- Simplify OHOS smoke test: hash + RNG only (no botan_aead_*)
- Fix OHOS smoke test: use botan/ffi.h (C FFI) instead of C++ headers
- Fix OHOS linker: -lc++ -lc++abi instead of -lstdc++
- Fix OHOS linker: drop PKG_CONFIG_SYSROOT_DIR, add -L for botan lib
- Fix OHOS pkg-config: use absolute paths + BOTAN_STATIC=1
- Fix build-botan-ohos.sh: resolve botan-modules via absolute path
- Fix NDK clang++ binary name: hyphens, not underscores
- Fix function ordering in setup-ohos-ndk.sh
- Fix OHOS NDK setup: archive format + sysroot path
- Fix OHOS Rust target name + criterion --baseline flag
- Add OHOS (OpenHarmony) cross-compile target
- Architecture audit: 4 new TODOs (47-50) written and completed
- Mark TODO.finalize/36-46 as done; small DRY cleanup
- Fix three CI failures: clippy, typos, Windows paths

## [0.4.0] - 2026-07-24

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
- **`enprot keygen`, `sign`, `verify-sig`**: Ed25519 detached signatures (PQC Phase 1). Foundation for ML-DSA / ML-KEM / composites tracked in `TODO.finalize/10-12`.
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
- **Windows CI link failure**: `--library-suffix=-3` is redundant on Botan 3.x (the major version already adds `-3`); dropping it lets the static library name match the cargo link directive (`botan-3.lib`).

## [0.3.1] - 2020-10-05

- Initial public release.
