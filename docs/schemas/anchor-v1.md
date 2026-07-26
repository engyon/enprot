# EPT chain anchor format — `anchor/v1`

A chain anchor is a `CHAIN` directive in the EPT file that
attests to the file's state at a point in time. It carries a
signature from one or more signers over the file's payload hash.
See TODO.roadmap/17 (chain DAG) and TODO.roadmap/57 (multi-sig).

## Grammar (informal)

```
chain-line    := "// <( CHAIN " extfield+ " )>" newline
extfield      := key ":" value
key           := "parents" | "signer" | "signers" | "sig"
              | "sigs" | "payload" | "ts" | "mut"
              | "recipient-" <tag>   (forward-compat; preserved)
```

## Single-signer fields (default)

| Field | Required | Format |
|-------|----------|--------|
| `signer` | yes | `<alg>:<fp-hex>` (e.g. `ed25519:9f3a7b…`) |
| `sig` | yes | hex-encoded signature bytes |
| `payload` | yes | SHA3-256 hex (64 chars) |
| `parents` | no | comma-separated SHA3-256 hex hashes |
| `ts` | no | RFC 3339 timestamp |
| `mut` | no | human-readable mutation description |

## Multi-signer fields (TODO.roadmap/57)

When `co_signers` is non-empty, the anchor emits two additional
fields alongside the single-signer fields:

| Field | Format |
|-------|--------|
| `signers` | comma-separated `<alg>:<fp-hex>` (primary + co-signers) |
| `sigs` | comma-separated hex signatures (same order as `signers`) |

The single-signer `signer` and `sig` fields are still emitted
with the primary signer's values for backwards compatibility.
Old verifiers that don't know about `signers` will verify only
the primary signature.

## Signing bytes

The signature commits to a canonical byte sequence:

```
parents || signer || co_signers || timestamp || payload_hash
```

- `parents`: concatenated 32-byte hashes, in order
- `signer`: UTF-8 encoding of `<alg>:<fp-hex>`
- `co_signers`: concatenated UTF-8 of each `<alg>:<fp-hex>`
- `timestamp`: UTF-8 RFC 3339 string (omitted if `ts` absent)
- `payload_hash`: 32 raw bytes

The `mut` (mutations) field is NOT part of the signing bytes —
it's informational and can be edited without invalidating the
signature.

## Payload hash

SHA3-256 over the canonical serialization of the file tree at
the point this anchor was created. Recomputed by `verify-chain`
from the file content preceding the CHAIN directive. Mismatch
means the file was tampered after the anchor was created.

## Forward compatibility

Parsers MUST preserve unknown extfields verbatim. Verifiers MAY
ignore them. A future `anchor/v2` could add new fields (e.g.,
`policy_hash`, `merkle_root`) without breaking `v1` consumers.

## Example

Single-signer:
```
// <( CHAIN signer:ed25519:9f3a7b... payload:abc123... sig:def456... mut:encrypt+WORD=Agent_007 )>
```

Multi-signer (2 signers):
```
// <( CHAIN signer:ed25519:9f3a7b... sig:aaa111... signers:ed25519:9f3a7b...,ed25519:1c8d2e... sigs:aaa111...,bbb222... payload:abc123... mut:multi-sig+contract )>
```
