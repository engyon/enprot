# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`enprot` is the Engyon Protected Text (EPT) command-line tool — a confidentiality processor for text/source files. It parses host-language comments containing `BEGIN`/`END`/`STORED`/`ENCRYPTED`/`DATA` directives (between configurable left/right separators, default `// <(` … `)>`), then performs four idempotent transformations on the named segments: **store** (sanitize to CAS), **fetch** (restore from CAS), **encrypt**, and **decrypt**. The same document can be round-tripped; transformations are keyed by WORD.

It depends on **Botan** (currently pinned to 2.13.0 in CI) as the underlying crypto provider via the `botan` crate. AES-256-SIV is the default AEAD; SHA-3 / Argon2 / Scrypt / PBKDF2 are used for hashing and KDF.

## Build & test

Requires a recent Botan installed on the system (`brew install botan` on macOS; see `ci/install.sh` for the Linux build from source). Then:

```sh
cargo build                              # debug
cargo build --release                    # produces target/release/enprot
cargo test -- --nocapture                # full integration suite (output streamed)
cargo test <name>                        # single test by name substring
cargo fmt -- --check $(find src -name '*.rs')   # CI format gate — run before pushing
```

Integration tests in `tests/cli/*` invoke the built binary via `assert_cmd` (`Command::cargo_bin("enprot")`), so the binary must compile before tests run. Most tests copy a fixture out of `sample/` or `test-data/` into a tempdir before running.

There is no separate lint job; `cargo fmt --check` on `src/**/*.rs` is the only style gate.

## Architecture

The data flow is strictly: **parse → transform → write**, repeated once per input file. All three phases live in `src/etree.rs` and operate on the same `TextTree` (`Vec<TextNode>`). `app_main` in `src/lib.rs` is the orchestrator.

### `TextTree` / `TextNode` (etree.rs)

The intermediate representation. Five node kinds:
- `Plain(String)` — host-language text, preserved verbatim.
- `Data(Vec<u8>)` — raw ciphertext bytes (serialized as base64 across multiple `DATA` lines, 48 bytes per line — see `DATA_BYTES_PER_LINE`).
- `Stored { keyw, cas }` — a CAS pointer; `keyw` is `"ct"` when the stored blob is ciphertext rather than plaintext.
- `BeginEnd { keyw, txt }` — a BEGIN/END segment; transformation decisions key off `keyw`.
- `Encrypted { keyw, txt, extfields }` — must contain exactly one `Data` or `Stored` child. `extfields` carries PHC-encoded `pbkdf:` and `cipher:` metadata so encrypted blobs are self-describing.

`parse()` is line-oriented: lines not starting (after whitespace) with the left separator are folded into the preceding `Plain`; matching lines are dispatched via the `cmd_parsers` HashMap to `parse_begin`/`parse_end`/`parse_data`/`parse_stored`/`parse_encrypted`. `tree_write()` is the inverse unparser. `transform()` is where store/fetch/encrypt/decrypt actually mutate the tree; it recurses and consults the `ParseOps` sets (`store`, `fetch`, `encrypt`, `decrypt`) plus `passwords`.

### `ParseOps` (etree.rs)

Single mutable struct threaded through every phase. Holds: separator strings, the four transform keyword sets, `passwords` map, `casdir`, the active `CryptoPolicy`, PBKDF/cipher option structs, an RNG, a PBKDF cache, and a recursion `level` counter (bounded by `--max-depth`, default 100). When adding a new transform or option, this struct and `app_main`'s argument wiring are the only places that need to change.

### Crypto stack

- `src/crypto.rs` — hash/PBKDF wrappers over Botan. Two `phf` maps translate internal names (`aes-256-gcm`, `pbkdf2-sha512`, …) to Botan's spelling.
- `src/cipher.rs` — `SymmetricCipher` trait with two impls: `BotanCipher` (delegates to `botan::Cipher`) for `aes-256-siv` / `aes-256-gcm`, and a hand-rolled `AESGCMSIVCipher<C>` over the `aes-gcm-siv` crate (Botan 2.13 lacks GCM-SIV). `create()` dispatches on the alg name.
- `src/pbkdf.rs` — `derive_key()` with three modes: `legacy` (plain SHA3-512 truncation, for backward compat), timed (msec → Botan picks params, caches PHC string), and manual (`--pbkdf-params` overrides). `BOTAN_PBKDF_PARAM_MAP` carries the per-alg parameter ordering; adding a new KDF means adding an entry here **and** to `consts::VALID_PBKDF_ALGS`.
- `src/cas.rs` — content-addressed storage. Filename = SHA3-256 hex of the blob; `save()` is idempotent (skips if the file exists), `load()` re-verifies the hash. Default directory is `./cas` if it exists, else `.`.
- `src/prot.rs` — high-level `encrypt()`/`decrypt()`. `encrypt()` chooses IV handling based on cipher (SIV needs no IV; everything else does, and the IV is recorded in the `cipher:` extfield). `decrypt()` parses the PHC extfield to recover KDF + salt + params, falling back to legacy mode when absent.

### Policy layer (src/policy/)

`CryptoPolicy` trait (`mod.rs`) gates every crypto call via `check_hash` / `check_pbkdf` / `check_cipher` and supplies defaults. Two impls: `CryptoPolicyDefault` (permissive; argon2 + aes-256-siv) and `CryptoPolicyNIST` (whitelists sha3-{256,512}, pbkdf2-{sha256,sha512}, aes-256-gcm; enforces min salt/key length and 96-bit GCM IV). `--fips` forces NIST; on Linux it also auto-engages when `/proc/sys/crypto/fips_enabled` reads `1`. `--defaults <POLICY>` loads a policy's defaults without enforcement.

Adding a new policy = new file in `src/policy/`, `pub mod` line in `mod.rs`, an entry in `consts::VALID_POLICIES`, and an arm in `make_policy` (`lib.rs`).

### CLI wiring (lib.rs)

`app_main` builds the `clap::App`, parses, then translates matches into a `ParseOps`. The `csep_arg!` macro expands comma-separated lists (`-s a,b,c` → three entries). `-o`/`-p`/`-o` interact: each input gets an output either from the matching `-o` or `prefix + input`; `-` means stdin/stdout. Files are read, transformed in place, and written back — the binary never prompts unless a password is missing.

The `<( ENCRYPTED AUTHOR )>` block at the top of `app_main` is intentional: it's the README's self-demonstrating example. Don't "clean it up."

## Testing conventions

- **Unit tests** (`#[cfg(test)] mod tests` inside each `src/` file) cover crypto primitives with known-answer vectors (see `cipher.rs` for AES-GCM / GCM-SIV KATs).
- **Integration tests** live in `tests/cli/*.rs` and are aggregated through `tests/cli/mod.rs` + the single `[[test]] name = "integration"` target declared in `Cargo.toml`. They drive the compiled binary end-to-end with `assert_cmd` + `predicates`, using the `Fixture` helper (`tests/tests.rs`) to copy `sample/*.ept` or `test-data/*.ept` into a tempdir.
- **Golden files** in `test-data/` are checked in as expected outputs (e.g. `test-encrypt-agent007-{,gcm,gcm-siv}.ept`, `test-encrypt-store-agent007-{,argon2,geheim}.ept`). When changing crypto output format, regenerate these deliberately and explain why in the commit — they encode wire-format contracts.
- Tests use real Botan, real `ParseOps`, real files. No mocks.

## Release / packaging

Releases are tag-driven. Pushing a tag matching `[0-9]+\.[0-9]+\.[0-9]+` triggers `.github/workflows/deploy.yml`, which first **fails if `Cargo.toml`'s `version` doesn't match the tag** — bump the version in the same commit. The workflow cross-compiles static binaries (see `ci/build-static/` per-target pre/post scripts), uploads archives, then publishes to GitHub Releases, crates.io, and Snap Store (`snap/snapcraft.yaml`). Botan is built from source for the musl Linux target using modules listed in `ci/botan-modules`.
