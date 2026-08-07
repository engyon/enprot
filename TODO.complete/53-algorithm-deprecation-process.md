# 53 — Algorithm deprecation process

**Priority**: P1
**Status**: specified

## Problem

Cryptography evolves. Algorithms that were considered secure when
enprot was first released may later be broken:

- **SHA-1**: collisions demonstrated; should never be used.
- **AES-CBC**: padding-oracle attacks; replaced by AEADs.
- **3DES**: 64-bit block, vulnerable to birthday attacks.
- **RSA-1024**: factored; insufficient strength.
- **MD5**: catastrophic collisions.
- **HMAC-SHA1**: still acceptable but trending toward deprecation.
- **PBKDF2 with low iteration counts**: brute-forceable.

enprot has a `CryptoPolicy` trait that gates algorithms at runtime,
but there's **no documented process** for:

1. **Identifying** when an algorithm should be deprecated.
2. **Adding** the deprecation marker without breaking existing users.
3. **Removing** deprecated algorithms after a transition window.
4. **Communicating** the deprecation to users.

Without a process, deprecation happens ad-hoc (or not at all),
leaving users exposed to known-broken crypto.

## Goals

- A `DeprecationLevel` annotation on every supported algorithm.
- Deprecation levels: `Active`, `Deprecated(since, replacement)`,
  `Removed(since)`.
- The `CryptoPolicy` trait rejects `Removed` algorithms and warns
  on `Deprecated` ones.
- A documented schedule: deprecated → removed in N minor versions.
- Deprecation events are announced in CHANGELOG + release notes.

## Design

### Deprecation metadata

```rust
// src/crypto.rs (extended)

#[derive(Debug, Clone, Copy)]
pub enum DeprecationLevel {
    /// Active, no concerns.
    Active,
    /// Deprecated; users should migrate. `since` is the version
    /// that introduced the deprecation. `replacement` is the
    /// preferred algorithm (may be empty if no replacement exists).
    Deprecated { since: &'static str, replacement: &'static str },
    /// Removed; the policy refuses to use this algorithm. Present
    /// only for documentation — the policy doesn't list removed
    /// algorithms in its supported set.
    Removed { since: &'static str },
}

pub struct AlgorithmMeta {
    pub name: &'static str,
    pub kind: AlgKind,
    pub deprecation: DeprecationLevel,
}

pub const ALGORITHMS: &[AlgorithmMeta] = &[
    AlgorithmMeta { name: "aes-256-siv", kind: AlgKind::Cipher, deprecation: DeprecationLevel::Active },
    AlgorithmMeta { name: "aes-256-gcm-siv", kind: AlgKind::Cipher, deprecation: DeprecationLevel::Active },
    AlgorithmMeta {
        name: "aes-256-gcm",  // not misuse-resistant; AEAD but no SIV
        kind: AlgKind::Cipher,
        deprecation: DeprecationLevel::Deprecated {
            since: "0.5.13",
            replacement: "aes-256-gcm-siv",
        },
    },
    AlgorithmMeta {
        name: "legacy-sha3-512-truncation",
        kind: AlgKind::Pbkdf,
        deprecation: DeprecationLevel::Deprecated {
            since: "0.5.0",
            replacement: "pbkdf2-sha512",
        },
    },
];
```

### Policy enforcement

```rust
impl CryptoPolicy for CryptoPolicyDefault {
    fn check_cipher_alg_impl(&self, alg: &str) -> Result<()> {
        let meta = ALGORITHMS.iter().find(|m| m.name == alg)
            .ok_or_else(|| Error::Policy(format!("unknown cipher: {alg}")))?;
        match meta.deprecation {
            DeprecationLevel::Active => Ok(()),
            DeprecationLevel::Deprecated { since, replacement } => {
                eprintln!(
                    "WARN: cipher '{alg}' is deprecated since {since}; \
                     use '{replacement}' instead"
                );
                Ok(())
            }
            DeprecationLevel::Removed { since } => {
                Err(Error::Policy(format!(
                    "cipher '{alg}' was removed in {since}; use a current algorithm"
                )))
            }
        }
    }
}
```

### CLI surface

`enprot cap algorithms` lists all supported algorithms with their
deprecation status:

```
$ enprot cap algorithms
aes-256-siv       cipher    Active
aes-256-gcm-siv   cipher    Active
aes-256-gcm       cipher    Deprecated since 0.5.13 (use aes-256-gcm-siv)
pbkdf2-sha256     pbkdf     Active
pbkdf2-sha512     pbkdf     Active
argon2id          pbkdf     Active
```

### Deprecation schedule

| Level | Lifetime |
|---|---|
| Active | Forever (until a deprecation event) |
| Deprecated | ≥ 2 minor versions, or 1 major version |
| Removed | Permanent — never comes back |

Example timeline for `aes-256-gcm`:

- **0.5.13**: deprecated (warns on use).
- **0.7.0**: still deprecated (1 minor later).
- **1.0.0**: removed (next major).

### Process for adding a deprecation

1. Open an issue with the rationale (paper, NIST guidance, etc.).
2. Discuss in a maintainer meeting.
3. Land the `Deprecated` annotation + CHANGELOG entry.
4. Set the target-removal version.
5. On the target version: change `Deprecated` → `Removed`, drop the
   algorithm from `ALGORITHMS`.

## Implementation plan

1. Add `DeprecationLevel` + `AlgorithmMeta` to `src/crypto.rs`.
2. Populate `ALGORITHMS` with current algorithms + deprecation status.
3. Update `CryptoPolicy::check_cipher_alg_impl` to honor the level.
4. Add `enprot cap algorithms` subcommand.
5. Document the deprecation schedule in CONTRIBUTING.md.
6. Audit existing algorithms; mark any that should be deprecated.

## Test plan

- [ ] Each `DeprecationLevel` branch has a unit test.
- [ ] `enprot cap algorithms` produces the expected output.
- [ ] A `Removed` algorithm cannot be used (rejected by policy).
- [ ] CHANGELOG entries for deprecations are explicit.

## Out of scope

- Auto-detection of broken algorithms (would require a crypto
  advisory feed; defer).
- A `--allow-deprecated` flag (defer until a real user requests it).
- Migration tooling (covered by TODO #42 migration guide).
