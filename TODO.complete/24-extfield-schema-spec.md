# 24 — Extfield schema spec

**Priority**: P1
**Status**: specified

## Problem

EPT ENCRYPTED blocks carry extfields like `pbkdf:` and `cipher:`. Their format (PHC string for pbkdf, dash-delimited for cipher) is hand-rolled. There's no schema, no validation, no versioning.

## Goals

- Machine-readable schema for every extfield enprot emits.
- Versioned (`pbkdf:v1`, `cipher:v1`, `recipient:v1`).
- Forward-compat: unknown extfields with `x-` prefix are preserved verbatim; unknown without `x-` are errors.
- Schema published at `docs/schemas/extfields/`.

## Extfield inventory

| Name | Format | Example |
|---|---|---|
| `pbkdf` | PHC string | `pbkdf=argon2id$v=19$m=65536,t=3,p=4$abc$def` |
| `cipher` | `alg-version-mode[-det]` | `cipher=aes-256-siv` or `cipher=aes-256-gcm-siv-det` |
| `recipient` | `kind:base64` | `recipient=mlkem:BASE64PUBKEY` |
| `chain` | see [23-chain-anchor-spec] | |
| `kind` | enum | `kind=encrypted|stored|immutable|mutable` |
| `cas` | hex | `cas=sha3-256:HEX64` |

## Design

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "name", content = "value")]
pub enum Extfield {
    Pbkdf(PhcString),
    Cipher(CipherSpec),
    Recipient(RecipientSpec),
    Chain(ChainSpec),
    Kind(BlockKind),
    Cas(ContentHash),
    X(UnknownExtfield),   // x-* prefix
}
```

Validation: each variant has its own `FromStr` + `Display` (already partially exists in `src/extfield.rs`).

## Implementation plan

1. Audit `src/extfield.rs` for completeness vs. the inventory above.
2. Generate `docs/schemas/extfields/*.json` per extfield.
3. Add property tests: every variant round-trips through Display/FromStr.
4. Document at `docs/extfields.md`.

## Test plan

- [ ] Every extfield enprot emits validates against its schema.
- [ ] Unknown extfield with `x-` prefix preserved.
- [ ] Unknown extfield without `x-` prefix rejected.

## Out of scope

- New extfield names (separate proposals per feature).
- Compressed/extensible binary encoding (text stays the wire format).
