# 50 — Newtype wrappers for domain primitives

**Priority**: P1
**Status**: specified

## Problem

enprot passes domain identifiers around as raw strings and byte
arrays:

```rust
// Current state — many String-typed identifiers
pub struct ParseOps {
    pub passwords: HashMap<String, String>,        // word → password
    pub transforms: TransformSets<String>,         // word sets
    pub fname: String,                              // path-as-string
}
pub fn cas::save(blob: Vec<u8>, paops: &mut ParseOps) -> Result<String>;
//                                                                ^ hash as hex string
pub fn cas::load(hexhash: &str, paops: &mut ParseOps) -> Result<Vec<u8>>;
//                            ^ hash as hex string, unvalidated
```

This is the **stringly-typed anti-pattern**. Consequences:

- A `&str` parameter could be a hash, a WORD, a path, or a free-form
  message — the type system doesn't distinguish them.
- Bugs from passing the wrong string (e.g., swapping `word` and
  `password`) compile fine.
- Validation is deferred: a hash string isn't checked for valid hex
  until `cas::load` runs.
- APIs require doc comments to convey what each `&str` is; docs rot.

## Goals

- Every domain primitive has its own newtype: `Word`, `Hash`,
  `CasHash`, `AnchorHash` (already exists), `KeyFp` (already exists),
  `Password`, `ExtfieldName`, etc.
- Construction validates the input; the type guarantees invariants.
- APIs take/return newtypes, not raw strings.
- Conversion to/from raw strings happens at the boundaries (CLI,
  FFI, serialisation).

## Design

### Newtypes to add

```rust
// src/types.rs (new)

/// A WORD identifier — uppercase ASCII, 1–16 chars, no separators
/// except underscore. The canonical form of a transform target.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Word(String);

impl Word {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() || s.len() > 16 {
            return Err(Error::InvalidArg {
                arg: "word",
                reason: format!("WORD must be 1–16 chars, got {}", s.len()),
            });
        }
        if !s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(Error::InvalidArg {
                arg: "word",
                reason: format!("WORD must be uppercase ASCII + digits + underscore, got '{s}'"),
            });
        }
        Ok(Word(s))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for Word { /* ... */ }

/// A hex-encoded SHA3-256 hash (64 lowercase hex chars).
/// Constructed from a validated hex string; the bytes are verified
/// to be 32 bytes long.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct HashHex(String);

impl HashHex {
    pub fn from_hex_unchecked(s: impl Into<String>) -> Self {
        // Used by callers that just produced the hash via crypto::hexdigest.
        HashHex(s.into())
    }
    pub fn parse(s: &str) -> Result<Self> {
        let _ = hex::decode(s)?;  // validates hex + 32-byte length
        Ok(HashHex(s.to_lowercase()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

/// A CAS hash — same wire format as HashHex but a different type so
/// callers can't accidentally pass a payload hash where a CAS hash
/// is expected.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CasHash(HashHex);

/// A user-supplied password. Wrapped to mark it as secret — future
/// zeroization work (#51) can wipe these on drop without scanning
/// for `String` parameters.
#[derive(Debug, Clone, ZeroizeOnDrop)]   // when #51 lands
pub struct Password(String);

impl Password {
    pub fn new(s: impl Into<String>) -> Self { Password(s.into()) }
    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
}

/// Extfield key — known set (pbkdf, cipher, signer, payload, sig, ...)
/// or `x-<custom>`. Validated at construction so the parser doesn't
/// have to repeat the check.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ExtfieldName(&'static str);  // or String if dynamic
```

### Boundary conversion

The CLI parses `--word FOO` into a `Word`. If the input is invalid,
the user sees a clear error before any file is opened:

```rust
// src/cli/common.rs
pub fn parse_word(s: &str) -> result::Result<Word, String> {
    Word::new(s).map_err(|e| e.to_string())
}

// clap value_parser:
#[arg(value_parser = parse_word)]
pub word: Word,
```

### What stays as raw types

| Type | Why |
|---|---|
| `PathBuf` for paths | Already a newtype; `&str` would be a regression |
| `Vec<u8>` for blobs | Generic enough; specialised wrappers add noise |
| `String` for free-form messages | No invariant to enforce |

## Implementation plan

1. Add `src/types.rs` with `Word`, `HashHex`, `CasHash`, `Password`, `ExtfieldName`.
2. Add unit tests for each newtype's invariants.
3. Migrate `ParseOps` fields one at a time (`passwords`, `transforms`).
4. Migrate `cas::save`/`load` signatures.
5. Migrate `etree::TextNode` variants (Stored.cas, Encrypted.keyw, etc.).
6. Migrate `error::Error::Cas(String)` to `Error::Cas(CasHash, CasOp)`.
7. Update FFI to convert at the boundary.

Each step is its own commit. The migration is invasive but
mechanical; CI catches regressions.

## Test plan

- [ ] Each newtype has positive + negative construction tests.
- [ ] Compiler rejects code that swaps a `Word` for a `HashHex`.
- [ ] Existing tests pass unchanged (or with mechanical updates).
- [ ] `cargo doc` renders the newtypes with clear semantics.

## Out of scope

- Refined types (e.g., `Word<Encrypt>` vs `Word<Decrypt>` via PhantomData).
  Overkill until a real use case appears.
- Newtypes for algorithm names (`Aes256GcmSiv` etc.) — already
  covered by `CipherOptions.alg: String` + runtime validation.
- A `SemVer` newtype for version strings.
