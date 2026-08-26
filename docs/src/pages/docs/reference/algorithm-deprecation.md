---
title: "Algorithm Deprecation"
layout: ../../../layouts/DocPage.astro
---

# Algorithm Deprecation Process

**Version**: 1.0
**Status**: Normative
**Scope**: How enprot deprecates and removes cryptographic algorithms

## Overview

Cryptography evolves. Algorithms considered secure at release may
later be broken. This document defines the process for identifying,
deprecating, and removing algorithms from enprot.

## Deprecation Lifecycle

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│ Active   │ ──▶ │ Deprecated   │ ──▶ │ Removed     │ ──▶ │ Gone     │
│ (default)│     │ (warning)    │     │ (error)     │     │ (deleted)│
└──────────┘     └──────────────┘     └─────────────┘     └──────────┘
     │                   │                   │
     ▼                   ▼                   ▼
  Normal use      eprintln! warning     Error::Policy
  No warnings     + still works         + fails
```

### 1. Active (default)

The algorithm is fully supported. No warnings. May be used freely.

### 2. Deprecated (warning phase)

The algorithm still works but prints a deprecation warning to
stderr. Users should migrate to a replacement. Duration: at least
one minor release cycle.

Implementation: `CryptoPolicy` returns `Ok(())` from
`check_cipher_alg` but the encrypt path calls `eprintln!` with a
migration message (same pattern as the existing `--pbkdf legacy`
warning).

### 3. Removed (error phase)

The algorithm is rejected by `CryptoPolicy::check_cipher_alg`.
`enprot encrypt --cipher <deprecated>` fails with
`Error::Policy`. Users must migrate. Duration: at least one minor
release cycle.

### 4. Gone (deleted)

The algorithm is removed from the codebase entirely. The cipher
map entry, policy check, and any related code paths are deleted.

## Criteria for Deprecation

An algorithm should enter the deprecation lifecycle when ANY of:

1. **Published attack**: A practical attack is demonstrated (e.g.,
   SHA-1 collisions, AES-CBC padding oracle).
2. **Standards body recommendation**: NIST, IETF, or ISO withdraws
   or downgrades the algorithm.
3. **Industry consensus**: Major libraries (OpenSSL, Botan, BoringSSL)
   remove or deprecate it.
4. **Policy mismatch**: The algorithm doesn't meet the FIPS 140-3
   or Common Criteria requirements that enprot targets.

## Current Algorithm Status

| Algorithm | Status | Notes |
|---|---|---|
| `aes-256-siv` | Active | Default for non-deterministic mode |
| `aes-256-gcm` | Active | Botan backend |
| `aes-256-gcm-siv` | Active | RustCrypto backend (RFC 8452) |
| `aes-256-gcm-det` | Active | Deterministic mode (CAS dedup) |
| `aes-256-gcm-siv-det` | Active | Deterministic mode (CAS dedup) |
| `sha3-256` | Active | CAS hashing |
| `sha3-512` | Active | Legacy PBKDF mode |
| `argon2` | Active | Default PBKDF |
| `scrypt` | Active | Alternative PBKDF |
| `pbkdf2-sha256` | Active | NIST-compliant PBKDF |
| `pbkdf2-sha512` | Active | NIST-compliant PBKDF |
| `legacy` | Deprecated | Unsalted SHA3-512 truncation; warning printed |

## Implementation in enprot

### Policy layer (`src/policy/`)

The `CryptoPolicy` trait's `check_cipher_alg` method is the gate.
Deprecation is implemented in two phases:

**Deprecated phase**: Add the algorithm to a `DEPRECATED_ALGS`
constant in the policy. The `check_cipher_alg` method allows the
algorithm but the encrypt path prints a warning.

**Removed phase**: Remove the algorithm from `VALID_CIPHER_ALGS`.
The clap value parser rejects it before it reaches the policy.

### Communication

Deprecation announcements go in:

1. **CHANGELOG.md** — `### Deprecated` section per [Keep a Changelog].
2. **CLI warning** — `eprintln!` when the deprecated algorithm is used.
3. **Migration guide** — `docs/migrations/` entry explaining what to
   switch to.

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/

## Example: Deprecating `aes-256-siv`

1. **Minor release X.Y.0**: Add to `DEPRECATED_ALGS`. Print warning:
   ```
   Warning: aes-256-siv is deprecated and will be removed in a future
   release. Migrate to aes-256-gcm-siv (RFC 8452) for equivalent
   misuse-resistance with better performance.
   ```
   CHANGELOG: `### Deprecated: aes-256-siv — use aes-256-gcm-siv instead`

2. **Minor release X.(Y+1).0**: Remove from `VALID_CIPHER_ALGS`.
   `enprot encrypt --cipher aes-256-siv` fails with `Error::Policy`.
   CHANGELOG: `### Removed: aes-256-siv — use aes-256-gcm-siv`

3. **Minor release X.(Y+2).0**: Delete cipher map entry, BotanCipher
   support, and any related test fixtures.

## Out of scope

- Post-quantum migration (tracked in TODO #58).
- HSM-backed algorithm enforcement (tracked in TODO #56).
- Formal verification of constant-time properties (TODO #64).
