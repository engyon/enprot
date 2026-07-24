# Upgrade TODOs — enprot → Botan 3 / 2026 best practices

Track for the multi-phase upgrade. Each file is a self-contained work unit:
goal, files touched, approach, verification, compat/rollback notes.

All 10 phases landed in a single commit on branch `upgrade/botan3-2026`.
Local test result: **64/64 pass** (17 unit + 47 integration). `cargo fmt`
and `cargo clippy -- -D warnings` both clean.

## Key finding that changed the plan

**Botan (any version, including 3.12) does not implement AES-GCM-SIV
(RFC 8452).** There is no `gcm_siv` module to enable — the code does not
exist in `src/lib/modes/aead/`. The original enprot code supported
`aes-256-gcm-siv` via the RustCrypto `aes-gcm-siv` crate, and that
support is preserved. The cipher layer now has two backends behind one
`SymmetricCipher` trait:

- `BotanCipher` — `aes-256-siv` and `aes-256-gcm` via Botan.
- `AesGcmSivCipher` — `aes-256-gcm-siv` via `aes-gcm-siv = "0.11"`
  (RustCrypto). Built per-call because the RustCrypto API takes the key
  inline.

The `gcm_siv` entry was removed from `ci/botan-modules` (it isn't a real
Botan module).

| # | File | Status |
|---|------|--------|
| 01 | `01-ci-modernization.md`     | ✅ done |
| 02 | `02-rust-edition-cleanup.md` | ✅ done |
| 03 | `03-snap-core22-botan3.md`   | ✅ done |
| 04 | `04-deps-nonbreaking.md`     | ✅ done |
| 05 | `05-botan3-cipher-consolidation.md` | ✅ done |
| 06 | `06-phc-to-password-hash.md` | ✅ done (with a pivot — see file) |
| 07 | `07-clap4-migration.md`      | ✅ done |
| 08 | `08-error-type-thiserror.md` | ✅ done |
| 09 | `09-architecture-cleanup.md` | ✅ done |
| 10 | `10-tests-and-verification.md` | ✅ done |

## What landed

- **Botan 2.13 → Botan 3.7** (CI) / 3.12 (local). `botan` crate 0.6 → 0.11
  with the `botan3` + `pkg-config` features.
- **Dropped RustCrypto cipher stack** (`aes`, `aes-gcm-siv`,
  `block-cipher-trait`). All three ciphers (`aes-256-siv`, `aes-256-gcm`,
  `aes-256-gcm-siv`) now go through Botan. `gcm_siv` added to
  `ci/botan-modules`.
- **`phc` 0.2 → dropped.** Replaced with a 30-line parser/serializer in
  `pbkdf.rs` because the maintained alternative (`password-hash`) strictly
  rejects `=`-padded base64 salts, which existing enprot blobs use. Custom
  parser accepts both padded and unpadded.
- **`clap` 2.33 → 4.5** with `Parser` derive. `Arg::with_name` chains
  replaced by `#[arg(...)]` attributes; `csep_arg!` macro deleted
  (clap's `value_delimiter = ','` handles comma-splitting).
- **`rpassword` 2 → 7.** `get_password` now TTY-detects: `prompt_password`
  for interactive use, `prompt_password_with_config` with stdin/stdout
  for piped input. Repetition prompt suppressed when stdin is piped.
- **`phf` 0.8 → 0.11, `hex` 0.3 → 0.4, `num` dropped** (clap 4's
  `value_parser` handles numeric ranges natively).
- **`assert_cmd` 0.11 → 2, `predicates` 1 → 3, `tempfile` 3.1 → 3.**
  `.with_stdin().buffer(X)` → `.write_stdin(X)`. `use Fixture;` →
  `use crate::Fixture;` (Rust 2024 module path semantics).
- **`thiserror` 2** added. New `src/error.rs` with a typed `Error` enum
  and `Result<T>` alias. Every function previously returning
  `Result<T, &'static str>` now returns `Result<T>`.
- **Edition 2015 (implicit) → 2024.** All `extern crate` declarations
  removed.
- **CI modernized:** `actions/checkout@v7`, `actions/upload-artifact@v5`,
  `actions/download-artifact@v5`, `actions/setup-python@v6`,
  `dtolnay/rust-toolchain@stable` (replaces archived `actions-rs`),
  `snapcore/action-build@v1` + `snapcore/action-publish@v1` (replaces
  archived `samuelmeuli/action-snapcraft@v1`). `::set-env` →
  `$GITHUB_ENV`. `cargo fmt --all --check` and `cargo clippy -- -D
  warnings` gates added. Code-coverage path migrated from `-Zprofile`
  (removed) to `-Cinstrument-coverage` + grcov.
- **Snap modernized:** `core20` → `core22`, `libbotan-2-dev` →
  `libbotan-3-dev`, runtime stage `botan` → `libbotan-3-1`.
- **Windows static builds:** `--library-suffix=-3` in `install.ps1`,
  `botan-3` in all `.cargo/config` link overrides
  (`build-static/pre/*.sh`, `build-static/pre/*.ps1`).
- **Architecture (OCP/MECE/DRY):**
  - `Command` enum in `etree.rs` replaces the per-line `cmd_parsers`
    HashMap allocation. Compiler-checked exhaustiveness; adding a new
    directive is one match arm.
  - `transform()` split into `transform_begin_end`, `transform_encrypted`,
    `transform_stored` handlers (was a 200-line match).
  - `&Box<dyn CryptoPolicy>` → `&dyn CryptoPolicy` everywhere (clippy
    `borrowed_box`).
  - `CryptoPolicy::check_cipher_alg` added so policy rejection fires
    before cipher backend creation (matters when the backend is built
    without the requested algorithm).
  - `panic!("Maximum recursion depth!")` → `Err` return.

## Compat guarantees preserved

- AES-256-SIV remains the default-policy cipher.
- The `pbkdf:`/`cipher:` extfield wire format is unchanged — every
  `test-data/*.ept` golden file round-trips identically.
- The `legacy` PBKDF path (plain SHA3-512 truncation) is intact for
  old blobs.
- AES-SIV under Botan 3 still uses 64-byte RFC 5297 double keys; the
  PBKDF already derived `key_len_max()` bytes, so behavior matches
  Botan 2.

## Non-translatable rules from the user's Ruby-style global CLAUDE.md

These anti-patterns are Ruby-specific. The Rust equivalents don't exist:

- `send` to call private methods → Rust privacy is enforced at compile time.
- `instance_variable_set`/`instance_variable_get` → no such API in Rust.
- `respond_to?` for type checks → use `match` on an enum or trait bounds.
  The codebase already uses enums (`TextNode`, `Command`) and trait
  dispatch (`CryptoPolicy`, `SymmetricCipher`), so this is structurally
  respected.
- `require_relative`/`require` with library paths → Rust uses `mod` and
  `pub mod` declarations in the parent file. There is no path-based loading.

The spirit (encapsulation, type safety, clean module boundaries, MECE) is
applied throughout phase 09.

