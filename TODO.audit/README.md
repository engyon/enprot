# Architecture audit — post-upgrade enprot

A read-through of the codebase after PRs #57 and #58 (Botan 3 upgrade +
follow-ups). Findings ordered by impact, biggest first. Each finding is
labelled with the principle it touches and whether it's worth doing now,
later, or never.

## Status (July 2026)

Findings landed across the audit PRs:

- **A3 (etree module split)** — `src/etree.rs` → `src/etree/{mod,parse,transform,write,blob}.rs`. PR #72.
- **A4 (password module extraction)** — `src/password.rs` from `src/prot.rs`. PR #68.
- **A5 (policy AlgKind enum)** — replaced the stringly-typed `kind: &str` with `AlgKind { Cipher, Hash, Pbkdf }`. PR #69.
- **A7 (parse_encrypted_extfields context)** — threads `paops/lineno/line` so duplicate-extfield errors carry location. PR #70.
- **A2 (ExtField type)** — cipher extfield `format_cipher_extfield`/`parse_cipher_extfield`/`DEFAULT_CIPHER_ALG` move to `cipher.rs`; `prot.rs` uses the typed helpers. PR #71.
- **A8, A9, A13** — `app_main` returns `Result<()>`; `ParseOps::new` returns `Result<Self>`; CAS hash comparison documented as fine-without-constant-time. PR #67.

The remaining findings are deferred:

- **A1 (ParseOps decomposition)** — 78 field access sites across `etree/`, `lib.rs`, `prot.rs`. A multi-day refactor in its own right; needs careful staged PRs. `TODO.audit/` keeps this documented.
- **A6 (cipher registry)** — only 5 ciphers in `VALID_CIPHER_ALGS`; the `match` is fine. Defer until we have ~10+ ciphers.
- **A10 (proptest round-trip)** — would require adding `proptest` as a dev-dependency and writing property generators for valid EPT text. Defer.
- **A11 (README doctest)** — AsciiDoc has no native doctest infrastructure; would need a custom test runner that re-runs documented commands against a tempdir. High effort for low value. Defer.
- **A12 (benchmarks)** — no performance concerns today. Add a `criterion` harness when a perf regression surfaces.

## A1 — `ParseOps` is a god struct (model-driven, MECE, encapsulation)

Today `ParseOps` carries 14+ fields spanning four concerns: parsing
configuration, transform targets, crypto configuration, and recursion
state. Any new feature adds another field; nothing about the struct
tells you which fields cluster.

**Decomposition:**

```rust
pub struct Separators { pub left: String, pub right: String }

pub struct Transforms {
    pub store: HashSet<String>,
    pub fetch: HashSet<String>,
    pub encrypt: HashSet<String>,
    pub decrypt: HashSet<String>,
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
    level: usize,           // private — only `transform` and `parse` mutate it
}
```

The好处:

- Callers that only need crypto (`prot::encrypt`) take `&mut CryptoConfig`
  instead of `&mut ParseOps`. Today they take the whole struct and ignore
  90% of it.
- Tests can build a `CryptoConfig` without constructing a full
  `ParseOps`.
- The `level` field becomes truly private (no `pub` escape hatch).

**Verdict:** do it. Schedule after #22 (subcommand CLI) so the
decomposition can inform `CommonArgs` / `EncryptOpts`.

## A2 — Wire-format fields are scattered (single source of truth)

The `pbkdf:` and `cipher:` extfield shapes are encoded by:

- `pbkdf::format_phc` — writes the pbkdf field.
- `pbkdf::parse_phc` — reads the pbkdf field.
- `prot::parse_cipher_extfield` — reads the cipher field.
- `etree::parse_encrypted_extfields` — splits out the trailing
  `key:value` tokens from a `<( ENCRYPTED word ... )>` line.
- `etree::tree_write` — writes the `key:value` tokens back out for
  `Encrypted` nodes.

Five places, three of which know the `pbkdf:` / `cipher:` semantics.
Adding a new extfield (e.g. `aad:` for #39, or `sig:` for #40) means
touching all five.

**Decomposition:** a typed `ExtField` enum:

```rust
pub enum ExtField {
    Pbkdf(PhcString),
    Cipher(CipherSpec),
    // future: Aad(Vec<u8>), Sig(Signature), ...
}

impl ExtField {
    pub fn parse(token: &str) -> Result<Self>;
    pub fn to_token(&self) -> String;
}
```

`etree::parse_encrypted_extfields` returns `BTreeMap<String, ExtField>`,
`tree_write` writes them via `to_token`. `prot::encrypt`/`decrypt` ask
for the typed fields they need instead of re-parsing strings.

**Verdict:** do it. Schedule alongside #39 since #39 likely adds a new
extfield for the derived-IV case (or at least reuses the cipher field
shape with a new alg name).

## A3 — `etree.rs` is ~900 lines (MECE)

The single `etree.rs` covers: the parser dispatch table, the per-command
parsers, the unparser, the transform tree-walk, the per-node transform
handlers, the blob<->tree adapters, and a sizeable test module. Five
distinct responsibilities.

**Decomposition:**

```
src/etree/
    mod.rs         — ParseOps, TextNode, TextTree, Separators, Transforms
    parse.rs       — parse() + parse_begin/end/data/stored/encrypted
    write.rs       — tree_write()
    transform.rs   — transform() + per-node handlers
    blob.rs        — blob_to_tree / tree_to_blob
    tests.rs       — #[cfg(test)] mod tests
```

Public surface (`mod.rs` re-exports) stays the same. Each submodule is
200-300 lines.

**Verdict:** do it. Mechanical; pairs naturally with A1.

## A4 — `prot::get_password` mixes concerns (encapsulation)

It both prompts and verifies. The verification is interactive-only
(TTY); the prompt routing is shared. Splitting:

```rust
// src/password.rs
pub fn read_password(prompt: &str) -> Result<String>;
pub fn read_and_verify_password(name: &str) -> Result<String>;
```

`prot.rs` calls `password::read_and_verify_password`. Cleans up the
import of `rpassword` from `prot.rs` (which today is the only consumer).

**Verdict:** do it. Tiny refactor.

## A5 — `policy::nist::check_alg` takes a stringly-typed kind (type safety)

```rust
fn check_alg(kind: &str, alg: &str) -> Result<(), String>
where kind ∈ {"Cipher", "Hash", "PBKDF"}  // not enforced by the type system
```

Replace with an enum:

```rust
enum AlgKind { Cipher, Hash, Pbkdf }
```

Compiler enforces exhaustive match. Adding a new kind (e.g. `Mac` for
#39's HMAC support) is a localized change.

**Verdict:** do it, trivially.

## A6 — Cipher dispatch is a `match` on alg name (OCP, performance)

```rust
pub fn encryption(alg: &str) -> Result<Box<dyn SymmetricCipher>> {
    match alg {
        "aes-256-gcm-siv" => Ok(Box::new(AesGcmSivCipher::new(...))),
        _ => Ok(Box::new(BotanCipher::create(alg, ...)?)),
    }
}
```

For three ciphers, fine. With the two new `-det` variants from #39 it's
five. Could use a registry:

```rust
type Ctor = fn(CipherDirection) -> Result<Box<dyn SymmetricCipher>>;
static CIPHER_REGISTRY: phf::Map<&'static str, Ctor> = phf_map! { ... };
```

**Verdict:** maybe. The match arms are readable and the compiler checks
them. A registry starts to pay off at ~8 ciphers. Defer.

## A7 — `parse_encrypted_extfields` returns `Error::Parse` with empty file/lineno (correctness)

```rust
return Err(Error::Parse { file: String::new(), lineno: 0, msg: ... });
```

The function doesn't know the file/lineno context. Fix: thread a
`&ParseOps` (or just `(&str, i32)` — filename and lineno) through. Cheap.

**Verdict:** do it.

## A8 — `app_main` returns `()` (correctness, encapsulation)

`app_main` exits the process directly via `std::process::exit(1)` on
error. That blocks callers — particularly the unit tests in
`tests/cli/pbkdf.rs` that call `enprot::app_main(vec![...])` and would
like to assert on the error.

Change `app_main` to return `Result<(), Error>`. `main.rs` becomes:

```rust
fn main() {
    if let Err(e) = enprot::app_main(std::env::args()) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
```

Tests can call `app_main(...).unwrap_err()`.

**Verdict:** do it. Improves testability meaningfully.

## A9 — `ParseOps::new` panics if RNG fails (correctness)

```rust
let rng = botan::RandomNumberGenerator::new().expect("Failed to initialize RNG");
```

Real failure mode (Botan not installed, system RNG unavailable) panics
inside library code. Make `ParseOps::new` return `Result<Self>`. Caller
in `app_main` already runs in a `Result` context.

**Verdict:** do it.

## A10 — No property-based round-trip test (specs)

Today's test suite checks `encrypt(decrypt(x)) == x` for a handful of
specific `x`s (the golden files). A property test using `proptest` would
generate random `TextTree`s and assert round-trip equality. Cheap
insurance for the crypto layer.

**Verdict:** do it. Add `proptest` as dev-dependency.

## A11 — README examples aren't tested (specs)

The tutorial section in `README.adoc` walks through `enprot sample/test.ept -s GEHEIM` etc. Those commands aren't run by CI, so they rot silently. Either:

- Convert to `markdown` doctests (`rustdoc`-style), or
- Add a `tests/readme.rs` that re-runs the documented commands against a
  tempdir and asserts the documented output.

AsciiDoc doesn't have native doctests; the second approach is more
practical.

**Verdict:** do it. Especially important after #22 changes the CLI
shape.

## A12 — No benchmarks (performance)

Two questions benchmarks would answer:

- How slow is `--pbkdf argon2` vs `--pbkdf pbkdf2-sha512` at default
  msec settings? (User-facing.)
- Does the `Command` enum dispatch in `parse()` actually beat the old
  per-line HashMap? (Internal curiosity.)

`criterion` benchmarks in `benches/`. Adds a dev-dep; doesn't run in CI
unless we add a workflow.

**Verdict:** nice-to-have. Add after the audit-driven refactors land so
we benchmark the post-refactor shape.

## A13 — CAS hash comparison isn't constant-time (security)

```rust
if hexhash != verify { return Err(...); }
```

In theory this leaks information about how many leading characters
match. In practice, the hash is derived from the file contents (CAS
semantic), not from a secret, so the comparison isn't
secret-sensitive. Add a one-line comment explaining why non-constant-time is acceptable here.

**Verdict:** do it. One comment.

## Out of scope for this audit

- **`#[allow(dead_code)]` on cipher trait methods.** The `alg` and
  `key_len_min` accessors are only used in tests today. Removing them
  from the trait loses self-description; keeping them with the allow is
  fine. No change.
- **Botan vendoring.** `botan-src` would make hermetic builds possible
  but adds 50+ MB to the source tree. Skip.
- **`clap_complete` for shell completions.** Nice-to-have; can add
  alongside #22.
- **Tracing/logging.** `eprintln!` is fine for a CLI of this size.

## Suggested audit-PR slicing

- **Audit PR 1:** A1 + A3 + A4 (ParseOps decomposition, etree module
  split, password module). Big diff, mostly mechanical moves.
- **Audit PR 2:** A2 + A7 (ExtField type + parse context). Wire-format
  refactor.
- **Audit PR 3:** A5 + A8 + A9 + A13. Small correctness/clarity fixes.
- **Audit PR 4:** A10 + A11 + A12 (specs — proptest, README doctest,
  benchmarks).

Four audit PRs on top of the issue-triage PRs. Each is small enough to
review in one sitting.
