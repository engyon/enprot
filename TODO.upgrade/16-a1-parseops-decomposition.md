# A1 — Decompose `ParseOps` into smaller structs

## Problem

`ParseOps` is a god struct with 16 fields spanning four concerns:

- Parsing config: `max_depth`, `left_sep`, `right_sep`
- Transform targets: `store`, `fetch`, `encrypt`, `decrypt`
- Runtime state: `passwords`, `fname`, `casdir`, `verbose`, `level`
- Crypto config: `rng`, `policy`, `pbkdfopts`, `pbkdf_cache`, `cipheropts`

Callers that only need one concern (e.g. `prot::encrypt`, which only
reads the crypto knobs) take the whole struct and ignore the rest.
That hurts encapsulation and makes the tests construct a full
`ParseOps` when they need one piece.

78 field access sites across `etree/{mod,parse,transform,write,blob}.rs`,
`lib.rs`, and `prot.rs`.

## Approach

Decompose into three inner structs that each own a concern, leaving
`ParseOps` as the orchestrator:

```rust
pub struct Separators { pub left: String, pub right: String }

pub struct Transforms {
    pub store:  HashSet<String>,
    pub fetch:  HashSet<String>,
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
    level: usize,           // stays private
}
```

Field-access renames (78 sites):
- `paops.left_sep` → `paops.separators.left`
- `paops.right_sep` → `paops.separators.right`
- `paops.{store,fetch,encrypt,decrypt}` → `paops.transforms.{...}`
- `paops.{rng,policy,pbkdfopts,pbkdf_cache,cipheropts}` → `paops.crypto.{...}`

Mechanical; one sed script handles it.

## Why this is worth doing

- **Encapsulation**: `prot::encrypt` takes `&mut paops.crypto` instead of
  `&mut paops`. Future tests can build a `CryptoConfig` without the
  whole ParseOps.
- **Model-driven**: the struct shape reflects the domain (config /
  transforms / state / crypto).
- **MECE**: each concern has a single owner. Adding a new transform
  only touches `Transforms`; adding a new crypto knob only touches
  `CryptoConfig`.

## Files

- `src/etree/mod.rs` — `Separators`, `Transforms`, `CryptoConfig`,
  refactored `ParseOps`.
- `src/etree/{parse,transform,write,blob}.rs` — access-path updates.
- `src/lib.rs` — `app_main` writes through `paops.separators`,
  `paops.transforms`, `paops.crypto`.
- `src/prot.rs` — `encrypt`/`decrypt` take `&mut CryptoConfig` where
  they used to take individual fields.
- `src/cas.rs` — reads `paops.crypto.policy` instead of `paops.policy`.
- `src/etree/mod.rs::tests` — update ParseOps struct-literal construction.

## Verification

```
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

## Rollback

Revert the commit. The struct shape and access paths revert together
since they're in lockstep.
