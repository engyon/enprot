# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`enprot` is the Engyon Protected Text (EPT) command-line tool — a confidentiality processor for text/source files. It parses host-language comments containing `BEGIN`/`END`/`STORED`/`ENCRYPTED`/`DATA` directives (between configurable left/right separators, default `// <(` … `)>`), then performs four idempotent transformations on the named segments: **store** (sanitize to CAS), **fetch** (restore from CAS), **encrypt**, and **decrypt**. The same document can be round-tripped; transformations are keyed by WORD.

It depends on **Botan 3** (CI builds against 3.7.0; Homebrew ships 3.12.0) as the underlying crypto provider via the `botan` crate (`botan3` + `pkg-config` features). The `aes-256-gcm-siv` cipher is provided by the RustCrypto `aes-gcm-siv` crate because Botan does not implement RFC 8452. AES-256-SIV is the default AEAD; SHA-3 / Argon2 / Scrypt / PBKDF2 are used for hashing and KDF. Deterministic AEAD variants (`aes-256-gcm-det`, `aes-256-gcm-siv-det`) derive the nonce from plaintext via HKDF + HMAC so identical plaintexts produce identical ciphertexts (CAS dedup).

It also depends on **librnp** (the OpenPGP C library from Ribose) via `rnp-rs` for OpenPGP signature support. Install via `brew install rnp` (macOS), `apt install librnp-dev` (Debian/Ubuntu), or build from source. `ci/install.sh` handles Linux + macOS; Windows builds librnp via vcpkg (TBD). If `brew install rnp` reports conflicts, run `brew link --overwrite rnp` to expose headers under `$(brew --prefix)/include/rnp/`.

## Build & test

Requires Botan 3 and librnp installed on the system (`brew install botan rnp` on macOS — run `brew link --overwrite rnp` if it conflicts; see `ci/install.sh` for the Linux build from source). Then:

```sh
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build        # debug (macOS)
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build --release
cargo test                                                          # full suite
cargo test <name>                                                   # single test by name substring
cargo fmt --all --check                                             # CI format gate
cargo clippy --all-targets -- -D warnings                           # CI lint gate
```

Integration tests in `tests/cli/*` invoke the built binary via `assert_cmd` (`Command::cargo_bin("enprot")`), so the binary must compile before tests run. Most tests copy a fixture out of `sample/` or `test-data/` into a tempdir before running.

CI runs both `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` as required gates. Additional CI jobs: typos spell check (`typos.toml`), security audit (`cargo-audit` + `cargo-deny` via `deny.toml`), and concurrency cancellation to save CI minutes.

### Pre-commit hook

A local pre-commit hook mirrors the CI checks (fmt, clippy, typos). Install it once:

```sh
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Skip temporarily with `SKIP_PRECOMMIT=1 git commit ...`.

## CLI

The CLI is subcommand-style (issue #22): `enprot {encrypt,decrypt,store,fetch,encrypt-store,passthrough}`. Each subcommand takes WORDs via `-w`/`--word` (repeatable, also comma-separated) and input files as positional args. Common options (`-v`, `-k`, `-c`, `--policy`, etc.) have `global = true` and work before or after the subcommand name. Encrypt-specific options (`--pbkdf`, `--cipher`, etc.) live under the `encrypt` and `encrypt-store` subcommands.

`app_main` returns `Result<()>`; `main.rs` translates errors to `eprintln!` + `exit(1)`.

## Architecture

The data flow is strictly: **parse → transform → write**, repeated once per input file. The pipeline lives in `src/etree/` (a module split across `mod.rs`, `parse.rs`, `transform.rs`, `write.rs`, `blob.rs`) and operates on the `TextTree` (`Vec<TextNode>`). `app_main` in `src/lib.rs` is the orchestrator.

### `TextTree` / `TextNode` (etree/mod.rs)

The intermediate representation. Five node kinds:
- `Plain(String)` — host-language text, preserved verbatim.
- `Data(Vec<u8>)` — raw ciphertext bytes (serialized as base64 across multiple `DATA` lines, 48 bytes per line).
- `Stored { keyw, cas }` — a CAS pointer; `keyw` is `"ct"` when the stored blob is ciphertext rather than plaintext.
- `BeginEnd { keyw, txt }` — a BEGIN/END segment; transformation decisions key off `keyw`.
- `Encrypted { keyw, txt, extfields }` — must contain exactly one `Data` or `Stored` child. `extfields` carries PHC-encoded `pbkdf:` and `cipher:` metadata so encrypted blobs are self-describing.

`parse()` (in `etree/parse.rs`) is line-oriented: lines not starting (after whitespace) with the left separator are folded into the preceding `Plain`; matching lines are dispatched via the `Command` enum (`Begin`/`End`/`Data`/`Stored`/`Encrypted`). `tree_write()` (in `etree/write.rs`) is the inverse unparser (returns `Result<()>`; IO errors propagate). `transform()` (in `etree/transform.rs`) is where store/fetch/encrypt/decrypt actually mutate the tree; it dispatches per node kind to `transform_begin_end` / `transform_encrypted` / `transform_stored` and recurses.

### `ParseOps` (etree/mod.rs)

Single mutable struct threaded through every phase. **Decomposed** (audit A1) into three inner structs:

```rust
pub struct Separators { pub left: String, pub right: String }
pub struct Transforms {
    pub store: HashSet<String>, pub fetch: HashSet<String>,
    pub encrypt: HashSet<String>, pub decrypt: HashSet<String>,
}
pub struct CryptoConfig {
    pub policy: Box<dyn CryptoPolicy>,
    pub pbkdfopts: PBKDFOptions,
    pub cipheropts: CipherOptions,
    pub rng: Option<botan::RandomNumberGenerator>,
    pub pbkdf_cache: Option<PBKDFCache>,
}

pub struct ParseOps {
    pub max_depth: usize,
    pub separators: Separators,
    pub transforms: Transforms,
    pub passwords: HashMap<String, String>,
    pub fname: String,
    pub casdir: PathBuf,
    pub verbose: bool,
    pub crypto: CryptoConfig,
    pub level: usize,
}
```

Field access is through the nested paths: `paops.separators.left`, `paops.transforms.store`, `paops.crypto.rng`, `paops.crypto.policy`, etc. Pass `&*paops.crypto.policy` to get `&dyn CryptoPolicy`.

### Error handling (src/error.rs)

`Result<T>` is `std::result::Result<T, Error>` where `Error` is a `thiserror::Error` enum. Every public function returns `Result<T>`; no `Result<T, &'static str>` anywhere. `From<std::io::Error>`, `From<botan::Error>`, and `From<hex::FromHexError>` are implemented so `?` works at IO/FFI boundaries. `Error::botan(e)` and `Error::msg(s)` constructors cover the rest.

### Crypto stack

- `src/crypto.rs` — hash/PBKDF wrappers over Botan. `phf` maps translate internal names to Botan's spelling. Also exposes `hkdf_sha256` and `hmac_sha256` for the deterministic AEAD variants. All functions take `&dyn CryptoPolicy` (not `&Box<dyn …>`).
- `src/cipher.rs` — `SymmetricCipher` trait with **two backends** behind one trait:
  - `BotanCipher` for `aes-256-siv` and `aes-256-gcm` (Botan 3).
  - `AesGcmSivCipher` for `aes-256-gcm-siv` via the RustCrypto `aes-gcm-siv` crate. **Botan does not implement RFC 8452 AES-GCM-SIV in any version** — there is no `gcm_siv` module to enable.
  - `encryption(alg)` / `decryption(alg)` strip the `-det` suffix before dispatching. The cipher wire format (`format_cipher_extfield` / `parse_cipher_extfield` / `DEFAULT_CIPHER_ALG`) lives here too.
  - Trait methods take `&mut self` because botan 0.11+ requires it.
- `src/pbkdf.rs` — `derive_key()` with three modes: `legacy` (plain SHA3-512 truncation, deprecated), timed (msec → Botan picks params), and manual (`--pbkdf-params`). `format_phc` / `parse_phc` are the PHC wire-format helpers.
- `src/cas.rs` — content-addressed storage. Filename = SHA3-256 hex of the blob; `save()` is idempotent. Non-constant-time hash comparison is fine (content-derived, not secret-derived).
- `src/prot.rs` — high-level `encrypt()`/`decrypt()`. `encrypt()` validates cipher alg against policy BEFORE backend creation (`check_cipher_alg`), then handles IV (random for non-det, HKDF-derived for `-det`). `decrypt()` mirrors HKDF for det variants.
- `src/password.rs` — TTY-aware password reading. Interactive uses `prompt_password` (echo suppression); piped uses `prompt_password_with_config`. Repeat-verification is skipped when stdin isn't a TTY.

### Policy layer (src/policy/)

`CryptoPolicy` trait (`mod.rs`) gates every crypto call via `check_hash` / `check_pbkdf` / `check_cipher_alg` / `check_cipher` and supplies defaults. `check_cipher_alg` has a default impl that strips the `-det` suffix before delegating to `check_cipher_alg_impl`. The NIST policy uses an `AlgKind` enum (not stringly-typed) for the cipher/hash/pbkdf distinction. `--fips` forces NIST; on Linux also auto-engages from `/proc/sys/crypto/fips_enabled`.

### Deterministic AEAD (#39)

`aes-256-gcm-det` and `aes-256-gcm-siv-det` derive the IV from plaintext via:
1. `enc_key = HKDF-SHA256(master_key, "enprot-enc", 32)`
2. `iv_key = HKDF-SHA256(master_key, "enprot-iv", 32)`
3. `iv = HMAC-SHA256(iv_key, plaintext)[..12]`

Same `(password, plaintext)` → same ciphertext → CAS dedup works for encrypted segments.

## Testing conventions

- **Unit tests** (`#[cfg(test)] mod tests` inside `src/etree/mod.rs` and `src/cipher.rs`) cover crypto primitives with known-answer vectors.
- **Integration tests** in `tests/cli/*.rs` drive the compiled binary end-to-end with `assert_cmd`. Test files: `cipher`, `deterministic`, `encrypt_decrypt`, `encrypt_store`, `issue_15`, `misc`, `multi_file`, `pbkdf`, `pipe`, `policy`, `store_fetch`.
- **Property tests** in `tests/proptest_roundtrip.rs` — 256 random inputs per property; checks round-trip + determinism for the `-det` variants.
- **Golden files** in `test-data/` encode wire-format contracts.
- Tests use real Botan, real `ParseOps`, real files. No mocks.

## Release / packaging

Releases are tag-driven. Pushing a tag matching `[0-9]+\.[0-9]+\.[0-9]+` triggers `.github/workflows/deploy.yml`, which **fails if `Cargo.toml`'s `version` doesn't match the tag** — bump the version first. The workflow cross-compiles, uploads archives, publishes to GitHub Releases + crates.io + Snap Store. Dependabot keeps cargo + GHA deps current.

## OHOS (OpenHarmony) cross-compile

`.github/workflows/ohos.yml` builds enprot for `aarch64-unknown-linux-ohos`. Two related triples are in play:

- **Rust target**: `aarch64-unknown-linux-ohos` (with `unknown` vendor — Rust requires it).
- **NDK triple**: `aarch64-linux-ohos` (no vendor). Used for the sysroot path, `--target=` flag, and NDK install name. The clang binary itself is named after the Rust triple (`aarch64-unknown-linux-ohos-clang++`).

The pipeline:

1. `ci/setup-ohos-ndk.sh` — downloads `ohos-sdk-public` + `LLVM-19` from the OpenHarmony daily_build API, extracts both, replaces the SDK's MULTIARCH sysroot with a relative symlink to the LLVM-19 PER-ARCH sysroot (the two-sysroots problem; see `docs/ohos-porting-guide.md`).
2. `ci/build-botan-ohos.sh` — cross-compiles Botan 3 statically via `configure.py` with `--cc-bin=$NDK/llvm/bin/aarch64-unknown-linux-ohos-clang++` + `--cc-abi-flags="--target=aarch64-linux-ohos --sysroot=..."`. Static build avoids `.so` code-signing.
3. `cargo build --target aarch64-unknown-linux-ohos --release` — sets `PKG_CONFIG_PATH`, `PKG_CONFIG_ALLOW_CROSS=1`, `PKG_CONFIG_SYSROOT_DIR` (pointing at `llvm-19/sysroot/<ndk-triple>`), and `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_*` env vars for the linker.
4. Verification in `ghcr.io/hqzing/dockerharmony:latest` (real OHOS userland via qemu binfmt) using `ci/ohos-smoke.c` (Botan hash + AEAD round-trip via the C FFI).

The NDK (~4 GB) is cached across CI runs via `actions/cache@v4` keyed on the setup script's hash. The workflow is `continue-on-error: true` until the cross-compilation is verified green; drop the flag and add `ohos` to required status checks once stable.

## Upgrade history

The codebase went through Botan 2 → Botan 3 (PR #57), clap 2 → clap 4 subcommands (PR #62), and an architecture audit (PRs #67-#82) that decomposed `ParseOps`, split `etree.rs` into a module, extracted the password module, typed the cipher wire format, added property-based tests, and moved `app_main` to return `Result`. Plans in `TODO.upgrade/` and `TODO.audit/`.
