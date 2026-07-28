# 02 — RSD spec conformance

**Priority**: P0
**Status**: done (audit); bridge work tracked in 05-07

## Problem

enprot drifted from the RSD spec. The spec lives at
`../engyon/rsd-engyon-syntax` (Ribose Standard, RSD 12001:2018) and
is the normative source of truth for EPT syntax. enprot's
implementation uses different vocabulary in several places and
omits spec-mandated features entirely.

Worse: enprot's README didn't reference the RSD spec at all, so
external readers had no way to know there WAS a normative spec.

## What the spec mandates (and enprot's status)

### Core directives

| Spec | enprot today | Status |
|---|---|---|
| `LEFT_SEP` / `RIGHT_SEP` (configurable separators) | `Separators` struct | ✅ aligned |
| `<( STATEMENT )>` annotation form | same | ✅ aligned |
| `CLASSIFY <group> <alg>` / `UNCLASSIFY <group>` | `BEGIN <word>` + `encrypt` transform | ⚠️ vocabulary drift |
| `CLASSIFIED <group> <alg>:<base64\|sha384>` | `ENCRYPTED <word> [hash] pbkdf:… cipher:…` | ⚠️ field shape differs |
| `SIGNED <name> <alg>` / `SIGNATURE <name> <alg>:…` | `CHAIN` anchor with `signer:`/`sig:` extfields | ⚠️ different surface, equivalent semantics |
| `IMMUTABLE <name> sha384=…` / `MUTABLE <name>` / `MUTED <name> sha384=…` | not implemented | ❌ missing (TODO 05) |
| `KEY <name> sha384=… \| base64=…` / `UNKEY <name>` | not implemented | ❌ missing (TODO 06) |
| `CERT <name> sha384=… \| base64=…` / `UNCERT <name>` | not implemented | ❌ missing (TODO 06) |

### Algorithm vocabulary

Spec baseline: AES-256, SHA2-384, ECDSA P-384, RSA-3072 (CNSA suite).
Spec calls out: SM4, Kuznyechik, SM3, Streebog as national
alternatives.

enprot today: AES-256-SIV/GCM/GCM-SIV (with deterministic variants),
SHA-3, Ed25519, ML-DSA, ML-KEM. **Different choices, but compatible
with the spec's "flexible approach to cryptographic core
algorithms".**

### Cryptographic realization

Spec calls for:
- **Deterministic AEAD** (so identical input produces identical
  ciphertext → CAS deduplication). ✅ enprot ships `aes-256-gcm-det`
  and `aes-256-gcm-siv-det`.
- **Deterministic signatures** (RFC 6979 ECDSA or equivalent).
  ✅ enprot's Ed25519 is naturally deterministic.
- **AEAD with AAD** for context binding (restrict how sections move
  between documents). ❌ not yet implemented.
- **Optional DEFLATE compression before encryption.** ❌ not
  implemented.

### Key management

Spec calls for:
- Passphrase-derived keys (Argon2 etc.) — ✅ enprot has this.
- Access-restricted local key files — ✅ PemSigner.
- SmartCards / HSMs — ❌ pending Confium integration.
- Online identity provider (SAML) — ❌ pending.
- Timed declassification via notary — ❌ pending.
- **k-of-n group control** — ❌ pending Confium FROST.

## What this TODO does

1. **Reference the RSD spec from README** (done — added link).
2. **Document the vocabulary drift** (done — table above).
3. **Track closure of each gap** in TODOs 05-07.

## Acceptance criteria

- [x] README references RSD spec at `../engyon/rsd-engyon-syntax`
- [x] Spec conformance table exists in this TODO
- [x] Gaps tracked: 05 (IMMUTABLE/MUTABLE/MUTED), 06 (KEY/CERT),
      07 (vocabulary bridge / CLASSIFY alias)

## Decision: don't rename, document the bridge

Renaming `BEGIN/END` to `CLASSIFY/UNCLASSIFY` would break every
existing EPT document. Instead, add `CLASSIFY`/`UNCLASSIFY` as
parser aliases for `BEGIN/END` with `encrypt` intent, and document
the mapping in the RSD spec's deviation annex (TODO 07). The wire
format stays `ENCRYPTED` for backward compatibility.

## Cross-references

- RSD spec: `../engyon/rsd-engyon-syntax/sections/04-syntax.adoc`
- [[01-strategic-vision]]
- [[05-immutable-mutable-blocks]]
- [[06-key-cert-scoping]]
- [[07-spec-vocabulary-bridge]]
