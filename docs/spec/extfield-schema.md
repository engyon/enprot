# ExtField Schema Specification

**Version**: 1.0  
**Status**: Normative  
**Scope**: Typed ExtField wire format for EPT directives

## 1. Overview

ExtFields are metadata key:value pairs that appear inside EPT
directives. They carry self-describing parameters so encrypted blobs
and anchor blocks are fully self-contained.

This spec defines the typed schema for both:
- **EncryptedExtField** — fields on ENCRYPTED segments
- **AnchorExtField** — fields on CHAIN/anchor segments

## 2. Wire Format

ExtFields appear as space-separated `key:value` pairs after the WORD
and optional hash in a directive:

```
// <( ENCRYPTED <word> <hash>? <extfield>* )>
```

Values are URL-encoded. Unknown keys are preserved as `Unknown(key,
value)` for forward compatibility.

## 3. EncryptedExtField

Typed enum for fields on ENCRYPTED segments.

### Variants

| Variant           | Wire key       | Value format                        |
|-------------------|---------------|-------------------------------------|
| `Pbkdf`           | `pbkdf`       | PHC string ($argon2id$... or $pbkdf2-...) |
| `Cipher`          | `cipher`      | Algorithm name (e.g., `aes-256-gcm-siv`) |
| `Recipients`      | `recipients`  | Comma-separated fingerprints        |
| `RecipientMlKemCt`| `r:<fp>`      | Base64 ML-KEM ciphertext for recipient |
| `Attribute`       | `attr:<name>` | URL-encoded attribute value         |
| `Unknown`         | `<any>`       | Preserved verbatim                  |

### Example

```
pbkdf:$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$<hash>
cipher:aes-256-gcm-siv
recipients:abc123,def456
r:abc123:<base64-mlkem-ct>
attr:classification:confidential
```

### Round-Tip

`into_entry()` / `from_entry()` convert between the typed enum and
the wire-format `(key, value)` pair. Unknown keys round-trip through
the `Unknown` variant without data loss.

## 4. AnchorExtField

Typed enum for fields on CHAIN/anchor segments.

### Variants

| Variant    | Wire key     | Value format                         |
|------------|-------------|--------------------------------------|
| `Signer`   | `signer`    | Single key fingerprint               |
| `Signers`  | `signers`   | Comma-separated fingerprints         |
| `Payload`  | `payload`   | Hex SHA3-256 of the payload          |
| `Sig`      | `sig`       | Base64 signature (single signer)     |
| `Sigs`     | `sigs`      | Comma-separated base64 signatures    |
| `Parents`  | `parents`   | Comma-separated hex parent hashes    |
| `Timestamp`| `ts`        | Unix timestamp (seconds)             |
| `Mutation` | `mut`       | Mutation type (create/update/delete) |
| `Unknown`  | `<any>`     | Preserved verbatim                   |

### Example

```
signer:abc123def456
sig:<base64-signature>
parents:a1b2c3d4,e5f6g7h8
ts:1722259200
mut:create
```

## 5. Versioning Strategy

- **Forward compatibility**: Unknown keys are preserved as
  `Unknown(String, String)`. New fields added by future versions are
  not lost when round-tripped through older code.
- **Backward compatibility**: Old field names continue to work.
  Renamed fields map both old and new names to the same variant.
- **No version number in wire format**: The schema is identified by
  the key names themselves. Adding new keys is non-breaking.

## 6. Implementation

The typed enums are in `src/extfield.rs`:

```rust
pub enum EncryptedExtField {
    Pbkdf(String),
    Cipher(String),
    Recipients(Vec<String>),
    RecipientMlKemCt { fp: String, ct: Vec<u8> },
    Attribute { name: String, value: String },
    Unknown(String, String),
}

pub enum AnchorExtField {
    Signer(String),
    Signers(Vec<String>),
    Payload(String),
    Sig(Vec<u8>),
    Sigs(Vec<Vec<u8>>),
    Parents(Vec<String>),
    Timestamp(u64),
    Mutation(String),
    Unknown(String, String),
}
```

Both enums implement `into_entry() -> (String, String)` and
`from_entry(key, value) -> Self` for wire-format conversion.
