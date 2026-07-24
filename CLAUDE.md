# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`enprot` is the Engyon Protected Text (EPT) command-line tool — a confidentiality processor for text/source files. It parses host-language comments containing `BEGIN`/`END`/`STORED`/`ENCRYPTED`/`DATA` directives (between configurable left/right separators, default `// <(` … `)>`), then performs four idempotent transformations on the named segments: **store** (sanitize to CAS), **fetch** (restore from CAS), **encrypt**, and **decrypt**. The same document can be round-tripped; transformations are keyed by WORD.

It depends on **Botan 3** (CI builds against 3.7.0; Homebrew ships 3.12.0) as the underlying crypto provider via the `botan` crate (`botan3` + `pkg-config` features). The `aes-256-gcm-siv` cipher is provided by the RustCrypto `aes-gcm-siv` crate because Botan does not implement RFC 8452. AES-256-SIV is the default AEAD; SHA-3 / Argon2 / Scrypt / PBKDF2 are used for hashing and KDF.

## Build & test

Requires Botan 3 installed on the system (`brew install botan` on macOS; see `ci/install.sh` for the Linux build from source). Then:

```sh
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build        # debug (macOS)
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build --release
cargo test                                                          # full suite
cargo test <name>                                                   # single test by name substring
cargo fmt --all --check                                             # CI format gate
cargo clippy --all-targets -- -D warnings                           # CI lint gate
```

Integration tests in `tests/cli/*` invoke the built binary via `assert_cmd` (`Command::cargo_bin("enprot")`), so the binary must compile before tests run. Most tests copy a fixture out of `sample/` or `test-data/` into a tempdir before running.

CI runs both `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings` as required gates.

## Architecture

The data flow is strictly: **parse → transform → write**, repeated once per input file. All three phases live in `src/etree.rs` and operate on the same `TextTree` (`Vec<TextNode>`). `app_main` in `src/lib.rs` is the orchestrator.

### `TextTree` / `TextNode` (etree.rs)

The intermediate representation. Five node kinds:
- `Plain(String)` — host-language text, preserved verbatim.
- `Data(Vec<u8>)` — raw ciphertext bytes (serialized as base64 across multiple `DATA` lines, 48 bytes per line — see `DATA_BYTES_PER_LINE`).
- `Stored { keyw, cas }` — a CAS pointer; `keyw` is `"ct"` when the stored blob is ciphertext rather than plaintext.
- `BeginEnd { keyw, txt }` — a BEGIN/END segment; transformation decisions key off `keyw`.
- `Encrypted { keyw, txt, extfields }` — must contain exactly one `Data` or `Stored` child. `extfields` carries PHC-encoded `pbkdf:` and `cipher:` metadata so encrypted blobs are self-describing.

`parse()` is line-oriented: lines not starting (after whitespace) with the left separator are folded into the preceding `Plain`; matching lines are dispatched via the `Command` enum (`Begin`/`End`/`Data`/`Stored`/`Encrypted`) — `Command::from_keyword` returns `Option<Command>`, then a `match` calls the matching parser fn. `tree_write()` is the inverse unparser (returns `Result<()>`; IO errors propagate). `transform()` is where store/fetch/encrypt/decrypt actually mutate the tree; it dispatches per node kind to `transform_begin_end` / `transform_encrypted` / `transform_stored` and recurses, consulting the `ParseOps` sets (`store`, `fetch`, `encrypt`, `decrypt`) plus `passwords`.

### `ParseOps` (etree.rs)

Single mutable struct threaded through every phase. Holds: separator strings, the four transform keyword sets, `passwords` map, `casdir`, the active `CryptoPolicy` (as `Box<dyn CryptoPolicy>` — pass `&*paops.policy` to get `&dyn CryptoPolicy`), PBKDF/cipher option structs, an RNG, a PBKDF cache, and a recursion `level` counter (bounded by `--max-depth`, default 100). When adding a new transform or option, this struct and `app_main`'s argument wiring are the only places that need to change.

### Error handling (src/error.rs)

`Result<T>` is `std::result::Result<T, Error>` where `Error` is a `thiserror::Error` enum. Every public function returns `Result<T>`; no `Result<T, &'static str>` anywhere. `From<std::io::Error>`, `From<botan::Error>`, and `From<hex::FromHexError>` are implemented so `?` works at IO/FFI boundaries. `Error::botan(e)` and `Error::msg(s)` constructors cover the rest.

### Crypto stack

- `src/crypto.rs` — hash/PBKDF wrappers over Botan. `phf` maps translate internal names (`sha3-256`, `pbkdf2-sha512`, …) to Botan's spelling. All functions take `&dyn CryptoPolicy` (not `&Box<dyn …>`).
- `src/cipher.rs` — `SymmetricCipher` trait with **two backends** behind one trait:
  - `BotanCipher` for `aes-256-siv` and `aes-256-gcm` (Botan 3).
  - `AesGcmSivCipher` for `aes-256-gcm-siv` via the RustCrypto `aes-gcm-siv` crate. **Botan does not implement RFC 8452 AES-GCM-SIV in any version** — there is no `gcm_siv` module to enable. Don't try to "fix" this by routing GCM-SIV through Botan.
  - `encryption(alg)` / `decryption(alg)` dispatch on the alg name via a `match`. Adding a new cipher: new match arm + (if Botan-backed) entry in `BOTAN_CIPHER_ALG_MAP`.
  - Trait methods take `&mut self` because botan 0.11+ requires `&mut self` for `set_key`/`process`. Callers must bind `let mut enc = …`.
- `src/pbkdf.rs` — `derive_key()` with three modes: `legacy` (plain SHA3-512 truncation, prints a deprecation warning when used for *encryption* via `prot::encrypt`; decryption stays silent), timed (msec → Botan picks params, caches PHC string), and manual (`--pbkdf-params` overrides). `BOTAN_PBKDF_PARAM_MAP` carries the per-alg parameter ordering; adding a new KDF means adding an entry here **and** to `consts::VALID_PBKDF_ALGS`. `format_phc` / `parse_phc` are the wire-format helpers; the parser accepts both padded and unpadded base64 salts (existing enprot blobs use padding).
- `src/cas.rs` — content-addressed storage. Filename = SHA3-256 hex of the blob; `save()` is idempotent (skips if the file exists), `load()` re-verifies the hash. Default directory is `./cas` if it exists, else `.`.
- `src/prot.rs` — high-level `encrypt()`/`decrypt()`. `encrypt()` first validates the cipher algorithm against the policy via `check_cipher_alg` (so policy rejection fires even if the cipher backend doesn't implement the alg), then chooses IV handling based on cipher (SIV needs no IV; everything else does, and the IV is recorded in the `cipher:` extfield). `decrypt()` parses the PHC extfield via `pbkdf::parse_phc` to recover KDF + salt + params, falling back to legacy mode when absent.

### Policy layer (src/policy/)

`CryptoPolicy` trait (`mod.rs`) gates every crypto call via `check_hash` / `check_pbkdf` / `check_cipher_alg` / `check_cipher` and supplies defaults. `check_cipher_alg` is the algorithm-name-only check called before backend cipher creation; `check_cipher` additionally enforces IV-length rules after key/IV are known. Two impls: `CryptoPolicyDefault` (permissive; argon2 + aes-256-siv) and `CryptoPolicyNIST` (whitelists sha3-{256,512}, pbkdf2-{sha256,sha512}, aes-256-gcm; enforces min salt/key length, 1000-iteration minimum, and 96-bit GCM IV). `--fips` forces NIST; on Linux it also auto-engages when `/proc/sys/crypto/fips_enabled` reads `1`. `--defaults <POLICY>` loads a policy's defaults without enforcement.

Adding a new policy = new file in `src/policy/`, `pub mod` line in `mod.rs`, an entry in `consts::VALID_POLICIES`, and an arm in `make_policy` (`lib.rs`).

### CLI wiring (lib.rs)

`app_main` parses args via `Cli::parse_from(args)` where `Cli` is `#[derive(Parser)]` (clap 4 derive). The parsed fields are translated into a `ParseOps`. Comma-separated values (`-s a,b,c`) arrive pre-split thanks to `value_delimiter = ','` on each `#[arg]` — there is no `csep_arg!` macro anymore. `-o`/`-p`/input interact post-parse: each input gets an output either from the matching `-o` or `prefix + input`; `-` means stdin/stdout. Files are read, transformed in place, and written back — the binary never prompts unless a password is missing.

The `<( ENCRYPTED AUTHOR )>` block at the top of `app_main` is intentional: it's the README's self-demonstrating example. Don't "clean it up."

Password reading (`prot::get_password`) is TTY-aware: interactive use goes through `rpassword::prompt_password` (echo suppression, reads from `/dev/tty`); piped use goes through `prompt_password_with_config` with stdin/stdout, and the repeat-verification prompt is skipped when stdin isn't a TTY.

## Testing conventions

- **Unit tests** (`#[cfg(test)] mod tests` inside each `src/` file) cover crypto primitives with known-answer vectors (see `cipher.rs` for AES-GCM / GCM-SIV KATs).
- **Integration tests** live in `tests/cli/*.rs` and are aggregated through `tests/cli/mod.rs` + the single `[[test]] name = "integration"` target declared in `Cargo.toml`. They drive the compiled binary end-to-end with `assert_cmd` + `predicates`, using the `Fixture` helper (`tests/tests.rs`) to copy `sample/*.ept` or `test-data/*.ept` into a tempdir.
- **Golden files** in `test-data/` are checked in as expected outputs (e.g. `test-encrypt-agent007-{,gcm,gcm-siv}.ept`, `test-encrypt-store-agent007-{,argon2,geheim}.ept`). When changing crypto output format, regenerate these deliberately and explain why in the commit — they encode wire-format contracts.
- Tests use real Botan, real `ParseOps`, real files. No mocks.

## Release / packaging

Releases are tag-driven. Pushing a tag matching `[0-9]+\.[0-9]+\.[0-9]+` triggers `.github/workflows/deploy.yml`, which first **fails if `Cargo.toml`'s `version` doesn't match the tag** — bump the version in the same commit. The workflow cross-compiles static binaries (see `ci/build-static/` per-target pre/post scripts), uploads archives, then publishes to GitHub Releases, crates.io, and Snap Store (`snap/snapcraft.yaml`). Botan is built from source for the musl Linux target using modules listed in `ci/botan-modules`; AES-GCM-SIV comes from the RustCrypto crate which has no system dependency.

## Upgrade history

The branch `upgrade/botan3-2026` (merged via PR #57 as commit `998206a`) brought the codebase from Botan 2 / clap 2 / edition 2015 to Botan 3 / clap 4 / edition 2024 in one diff. The plan and per-phase notes live in `TODO.upgrade/`. Read `TODO.upgrade/README.md` first if you need context on why the architecture looks the way it does (especially the dual-cipher-backend split and the custom PHC parser).
