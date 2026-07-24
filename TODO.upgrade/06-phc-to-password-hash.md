# 06 — Replace `phc` with `password-hash`

## Goal

`phc = "0.2.0"` is unmaintained. Replace it with RustCrypto's `password-hash`
crate, which is the maintained PHC-string parser used by `argon2`, `scrypt`,
and `pbkdf2` crates.

## Files

- `Cargo.toml` — drop `phc`, add `password-hash = "0.5"`
- `src/pbkdf.rs` — `format_phc` rewrite
- `src/prot.rs` — `decrypt` PHC parsing

## Current usage

### Writer (`src/pbkdf.rs::format_phc`)

```rust
format!("${}${}${}", alg,
    params.iter().map(|v| format!("{}={}", v.0, v.1))
        .collect::<Vec<String>>().join(","),
    utils::base64_encode(salt).unwrap())
```

Format produced: `$alg$k=v,k=v$<base64salt>` (no rounds field, just params).

### Reader (`src/prot.rs::decrypt`)

```rust
let phc: phc::raw::RawPHC = pbkdf.parse()?;
let alg = phc.id();
let params: BTreeMap<String, usize> = phc.params()
    .iter().map(|v| (v.0.to_string(), v.1.parse().unwrap())).collect();
let salt = match phc.salt()? {
    phc::Salt::Ascii(s) => base64_decode(s)?,
    phc::Salt::Binary(b) => base64_decode(str::from_utf8(b).unwrap())?,
};
```

## Approach

### With `password-hash` 0.5

The crate parses any PHC-formatted string into a `PasswordHash` with an
`Ident` (algorithm), `Salt`, and `params` (a `BTreeMap<String, ParamValue>`).

Reader becomes:
```rust
use password_hash::{PasswordHash, Salt};
let ph = PasswordHash::new(pbkdf_str)
    .map_err(|_| "Failed to parse PHC")?;
let alg = ph.algorithm.as_str();
let params = ph.parameters.iter()
    .map(|(k, v)| (k.as_str().to_string(), v.decimal().unwrap_or(0) as usize))
    .collect();
let salt_str = ph.salt.map(|s| s.as_str()).ok_or("Missing salt")?;
let salt = utils::base64_decode(salt_str)?;
```

Writer stays custom (we cannot use `PasswordHash::generate` because we don't
have a real `PasswordHasher` impl — Botan does the KDF, we just emit the
string). Build the string with the same `format!` as before, validated by
round-trip parsing in a unit test.

### Why not migrate the KDF calls themselves to RustCrypto?

Doing so would let us drop the `botan` PBKDF path entirely. But it would
also change the param-tuning behavior (Botan's `derive_key_from_password_timed`
chooses params using internal heuristics that don't match RustCrypto's). To
preserve deterministic output for existing golden files, keep Botan as the
KDF and only swap the PHC serialization layer.

## Verification

```
cargo test pbkdf
cargo test --test integration   # round-trip tests must pass
```

Add a unit test that round-trips `format_phc` through `PasswordHash::new`
for each supported alg.

## Compat

The PHC string format is unchanged — old encrypted documents still parse.
