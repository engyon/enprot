# 61 — DRY: CryptoPolicyDefault factory + key file permissions + zeroize

**Priority**: P1
**Status**: specified

## Problem

Three independent cleanup gaps found during architecture audit:

### 1. CryptoPolicyDefault duplication (35 sites)

`Box::new(CryptoPolicyDefault {})` is repeated across 35 call
sites in cli.rs, kemenc.rs, provenance/mod.rs, scm/mod.rs,
merge/mod.rs, resolve/mod.rs. This is a DRY violation — adding
a new default policy constructor parameter requires touching 35
files.

### 2. Key file permissions

`keygen --out-priv builder.pem` writes the private key with
the process's default umask (typically 0644 on Unix). Private
keys should be 0600 (owner-read-only). On shared systems, a
world-readable private key is a credential leak.

### 3. Secrets not zeroed on drop

Passwords (`paops.passwords: HashMap<String, String>`) and
private key PEM strings live in heap-allocated `String`s. When
the process exits, the OS reclaims the memory but doesn't
zero it. A cold-boot or process-memory-dump attack can recover
the plaintext secrets. The `zeroize` crate provides
`Zeroizing<String>` that zeros memory on drop.

## Solution

### 1. Factory function

```rust
// in crypto.rs
pub fn default_policy() -> Box<dyn CryptoPolicy> {
    Box::new(CryptoPolicyDefault {})
}
```

Replace all 35 `Box::new(CryptoPolicyDefault {})` call sites
with `crypto::default_policy()`.

### 2. Key file permissions

```rust
// in cli.rs pki_keygen
use std::os::unix::fs::PermissionsExt;
std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
```

Guarded by `#[cfg(unix)]`.

### 3. Zeroize secrets

Add `zeroize` as a dependency. Wrap password and PEM fields:

```rust
use zeroize::Zeroizing;
pub passwords: HashMap<String, Zeroizing<String>>,
```

This is the largest of the three — every site that reads a
password needs to handle `Zeroizing<String>` vs `String`. Scope
to the most critical fields: passwords and private key PEMs on
`ParseOps` and in CLI handlers. Internal crypto buffers that
are short-lived don't need zeroize (they're overwritten by the
next operation).

## Acceptance criteria

- [ ] Zero `Box::new(CryptoPolicyDefault {})` call sites outside
      crypto.rs
- [ ] Private key files created by `keygen` are 0600 on Unix
- [ ] `zeroize` in Cargo.toml dependencies
- [ ] Passwords and PEM strings wrapped in `Zeroizing<>`
- [ ] Tests unchanged (zeroize is transparent at the API level)
