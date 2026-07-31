# Extfield schema spec (v1)

**Status**: spec
**Schema version**: v1
**Stability**: stable — additive changes only.

Extfields are the `key:value` pairs that decorate `ENCRYPTED`,
`CHAIN`, `STORED`, and other EPT directives. They're how a single
text directive carries structured metadata (cipher choice, PBKDF
parameters, recipient keys, signature material) without breaking
host-language syntax.

This document defines:

- Inventory of recognized extfield names.
- Wire format (grammar) for each.
- Validation rules.
- Forward-compatibility rules for unknown extfields.

## Inventory

| Name | Carried by | Format | Example |
|---|---|---|---|
| `pbkdf` | ENCRYPTED | PHC string | `pbkdf=argon2id$v=19$m=65536,t=3,p=4$abc$def` |
| `cipher` | ENCRYPTED | `alg-version-mode[-det]` | `cipher=aes-256-siv` |
| `recipient` | ENCRYPTED | `kind:base64` | `recipient=mlkem:BASE64PUBKEY` |
| `kind` | (any) | enum | `kind=encrypted` |
| `cas` | STORED / ENCRYPTED | `alg:hex` | `cas=sha3-256:abc...` |
| `index` | CHAIN | u64 | `index=42` |
| `parents` | CHAIN | comma-separated hex | `parents=abc,def` |
| `payload` | CHAIN | hex64 | `payload=abc...` |
| `signer` | CHAIN | `alg:hexfp` | `signer=ed25519:9f3a7b...` |
| `ts` | CHAIN | compact RFC 3339 | `ts=20260731T143000Z` |
| `sig` | CHAIN | hex | `sig=abc...` |
| `cert` | CHAIN (sigstore) | base64 PEM | `cert=MII...` |
| `rekor` | CHAIN (sigstore) | URL | `rekor=https://rekor.sigstore.dev/...` |
| `mut` | CHAIN | description | `mut=encrypt+SECRET` |
| `hashalg` | IMMUTABLE | hash algorithm | `hashalg=sha3-256` |
| `hash` | IMMUTABLE / MUTED | hex | `hash=abc...` |

## Grammar

```
extfield := key '=' value
key      := [a-z][a-z0-9-]*            # lowercase, dashes ok
value    := [^\s)]+                    # no whitespace, no ')'
```

Multiple extfields are space-separated inside the directive:

```
// <( ENCRYPTED SECRET pbkdf=... cipher=aes-256-siv )>
```

## Per-extfield validation

### `pbkdf` (PHC string)

Per the [PHC spec](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md):

```
$<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
```

- `id` ∈ { `argon2id`, `argon2i`, `argon2d`, `scrypt`, `pbkdf2-sha256`, `pbkdf2-sha512` }.
- `v`, params, salt, hash are algorithm-specific.
- Salt and hash are base64-no-padding.

enprot's parser: `src/pbkdf.rs::parse_phc`.

### `cipher`

Format: `<algorithm>-<key_bits>-<mode>[-det]`

- `<algorithm>` ∈ { `aes` } (more added as backends land).
- `<key_bits>` ∈ { `128`, `256` }.
- `<mode>` ∈ { `siv`, `gcm`, `gcm-siv` }.
- Trailing `-det` marks deterministic variants (nonce derived from plaintext).

Examples: `aes-256-siv` (default), `aes-256-gcm`, `aes-256-gcm-siv`,
`aes-256-gcm-det`, `aes-256-gcm-siv-det`.

### `recipient`

Format: `<kind>:<base64-blob>`

- `<kind>` ∈ { `mlkem`, `ed25519`, `x25519` }.
- `<base64-blob>` is the SPKI-encoded public key, base64-no-padding.

Multiple recipients allowed: one `recipient=` extfield per key.

### `cas`

Format: `<hashalg>:<hex>`

- `<hashalg>` ∈ { `sha3-256`, `sha-256` }.
- `<hex>` is the hex-encoded hash, length matching the algorithm.

### `signer`

Format: `<alg>:<hexfp>`

- `<alg>` ∈ { `ed25519`, `ml-dsa-65`, `composite-ed25519-ml-dsa`, `sigstore-keyless` }.
- `<hexfp>` is SHA3-256 of the DER SubjectPublicKeyInfo, 64 hex chars.

### `ts` (compact RFC 3339)

`YYYYMMDDTHHMMSSZ` (UTC only; the `Z` is mandatory).

Example: `20260731T143000Z` for 2026-07-31 14:30:00 UTC.

## Forward compatibility

Extfields with the `x-` prefix are user/extensions-specific and
**always preserved verbatim** by enprot:

```
// <( ENCRYPTED SECRET pbkdf=... x-custom-app=meta )>
```

Unknown extfields **without** `x-` prefix cause parse failure. This
catches typos (`chiper=` instead of `cipher=`) and prevents silent
data loss when an unknown extension is misinterpreted.

To add a new extfield to the spec:

1. Add it to the table above.
2. Add a parser in `src/extfield.rs`.
3. Bump the spec patch version (still v1; minor revision noted in changelog).
4. Old parsers that encounter the new extfield will reject the file
   until they're updated — this is intentional, because they couldn't
   verify the new semantic anyway.

## JSON Schema

The wire format is text; the JSON Schema below describes the parsed
representation used by `enprot inspect --format json` and by external
tooling.

```json
{
  "$id": "https://engyon.org/schemas/extfield-schema-v1.json",
  "$defs": {
    "ExtfieldMap": {
      "type": "object",
      "additionalProperties": false,
      "patternProperties": {
        "^x-": { "type": "string" }
      },
      "properties": {
        "pbkdf":     { "type": "string", "$ref": "#/$defs/PhcString" },
        "cipher":    { "type": "string", "$ref": "#/$defs/CipherSpec" },
        "recipient": { "type": "string", "$ref": "#/$defs/RecipientSpec" },
        "kind":      { "enum": ["encrypted", "stored", "immutable", "muted", "chain"] },
        "cas":       { "type": "string", "pattern": "^(sha3-256|sha-256):[a-fA-F0-9]+$" },
        "index":     { "type": "integer", "minimum": 0 },
        "parents":   { "type": "string", "pattern": "^[a-fA-F0-9]+(,[a-fA-F0-9]+)*$" },
        "payload":   { "type": "string", "pattern": "^[a-fA-F0-9]{64}$" },
        "signer":    { "type": "string", "pattern": "^[a-z0-9-]+:[a-fA-F0-9]+$" },
        "ts":        { "type": "string", "pattern": "^\\d{8}T\\d{6}Z$" },
        "sig":       { "type": "string", "pattern": "^[a-fA-F0-9]+$" },
        "cert":      { "type": "string", "pattern": "^[A-Za-z0-9+/=]+$" },
        "rekor":     { "type": "string", "format": "uri" },
        "mut":       { "type": "string" },
        "hashalg":   { "enum": ["sha3-256", "sha3-512", "sha-256", "sha-512"] },
        "hash":      { "type": "string", "pattern": "^[a-fA-F0-9]+$" }
      }
    },
    "PhcString": {
      "type": "string",
      "pattern": "^\\$(argon2(id|i|d)|scrypt|pbkdf2-(sha256|sha512))(\\$[^\\s)]+)*$"
    },
    "CipherSpec": {
      "type": "string",
      "enum": [
        "aes-128-gcm", "aes-256-gcm",
        "aes-256-siv",
        "aes-256-gcm-siv",
        "aes-256-gcm-det", "aes-256-gcm-siv-det"
      ]
    },
    "RecipientSpec": {
      "type": "string",
      "pattern": "^(mlkem|ed25519|x25519):[A-Za-z0-9-_]+$"
    }
  }
}
```

## See also

- [`ept-wire-format-v1.md`](ept-wire-format-v1.md) — overall file shape.
- [`chain-anchor-v1.md`](chain-anchor-v1.md) — CHAIN-specific extfield semantics.
- `src/extfield.rs` — Rust parser implementation.
