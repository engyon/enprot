# 08 — Typed Error enum (thiserror)

## Goal

Replace every `Result<T, &'static str>` in `src/` with a typed
`Result<T, Error>` backed by `thiserror::Error`. The string errors lose
context, can't carry the failing algorithm/file/line, and force `eprintln!`
at every site. A typed enum is MECE, OCP-friendly (new failure mode = new
variant), and removes a long tail of stringly-typed matching.

## Files

- `Cargo.toml` — add `thiserror = "1"`
- `src/error.rs` — new file with the enum
- `src/lib.rs` — `mod error; pub use error::Error;`
- Every `src/*.rs` that returns `Result<_, &'static str>`:
  `cas.rs`, `cipher.rs`, `crypto.rs`, `etree.rs`, `pbkdf.rs`, `prot.rs`,
  `utils.rs`

## Approach

### The Error enum

```rust
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("botan: {0}")]
    Botan(String),

    #[error("hex decode: {0}")]
    Hex(String),

    #[error("base64: {0}")]
    Base64(String),

    #[error("cipher: {0}")]
    Cipher(String),

    #[error("hash algorithm '{0}' is not recognized")]
    UnknownHash(String),

    #[error("pbkdf: {0}")]
    Pbkdf(String),

    #[error("policy: {0}")]
    Policy(String),

    #[error("parse: {file}:{lineno}: {msg}")]
    Parse { file: String, lineno: i32, msg: String },

    #[error("CAS: {0}")]
    Cas(String),

    #[error("PHC string: {0}")]
    Phc(String),

    #[error("crypto: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

The `From<std::io::Error>` impl means `?` just works for IO calls.

### Botan error bridging

`botan::Error` is its own type. Add:

```rust
impl From<botan::Error> for Error {
    fn from(e: botan::Error) -> Self { Error::Botan(e.to_string()) }
}
```

Then `botan::HashFunction::new(...)?` produces `Error::Botan(...)`.

### Migration mechanics

For each function currently returning `Result<T, &'static str>`:
1. Change the signature to `Result<T>` (the new alias).
2. Replace `.map_err(|_| "static string")` with `.map_err(Error::Variant)`
   or `?` where a `From` impl exists.
3. Keep meaningful messages — turn `"Invalid CAS identifier"` into
   `Error::Cas("invalid CAS identifier (expected 64 hex chars)".into())`.

The parse path benefits most: today it does `eprintln!("{}:{}:{}", fname,
lineno, line)` then returns `Err("Parse error")`. After migration the parse
functions return `Err(Error::Parse { file, lineno, msg })` directly and the
top-level `app_main` does the printing once.

### Don't over-engineer

Don't introduce an error variant per call site — group by category. Don't
wrap clap's own error type (it has its own). Don't propagate errors from
`main()` with `anyhow` — we already translate to `process::exit(1)` in
`app_main`, keep that boundary.

## Verification

```
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

A grep should confirm no `&'static str` return types remain in `src/`:

```
grep -rn "&'static str" src/  # expect zero hits
```

## Rollback

Delete `src/error.rs`, revert function signatures. The bulk of the diff is
mechanical; reverting is straightforward.
