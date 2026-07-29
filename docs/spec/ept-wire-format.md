# EPT Wire Format Specification

**Version**: 1.0  
**Status**: Normative  
**Scope**: Engyon Protected Text (EPT) markup syntax

## 1. Overview

EPT (Engyon Protected Text) is a markup syntax embedded in
host-language comments. It enables confidentiality (encrypt/decrypt),
content-addressed storage (store/fetch), and provenance (sign/verify)
operations on segments of text within any text-based file.

The format is designed to be:
- **Host-language agnostic** — works in any language with a comment
  syntax (C, Rust, Python, shell, etc.)
- **Round-trippable** — transformations are idempotent
- **Merge-friendly** — segments are independent and commute at the
  block level
- **Human-readable** — the wire form is editable in any text editor

## 2. Separators

EPT directives appear between configurable left and right separators.
The defaults are:

```
// <( ... )>
```

- **Left separator**: `// <(`  (looks like a comment in C-like languages)
- **Right separator**: `)>`

Separators are configurable via CLI (`-l`/`--left-separator`,
`-r`/`--right-separator`) or config file.

A line is an EPT directive if and only if, after leading whitespace,
it begins with the left separator.

## 3. Directive Grammar

```bnf
directive     ::= ws left_sep ws command ws args ws right_sep
command       ::= "BEGIN" | "END" | "STORED" | "ENCRYPTED"
              | "DATA" | "CHAIN" | "CONFLICT"
              | "IMMUTABLE" | "MUTABLE" | "MUTED"
              | "KEY" | "UNKEY" | "CERT" | "UNCERT"
args          ::= word [ hash_spec ] [ extfields]
                | data_payload
                | name hash_spec
word          ::= identifier   ;; the WORD this segment belongs to
hash_spec     ::= hashalg "=" hexhash
hashalg       ::= "sha3-256" | "sha3-512" | "sha256" | ...
hexhash       ::= 1*64HEXDIG
extfields     ::= extfield *( ws extfield )
extfield      ::= key ":" value
data_payload  ::= 1*BASE64    ;; base64-encoded ciphertext, 48 bytes/line
```

## 4. Segment Types

### 4.1 BEGIN / END

Opens/closes a named segment. The WORD identifies the password group.

```
// <( BEGIN WORD )>
...plaintext...
// <( END WORD )>
```

### 4.2 ENCRYPTED

An encrypted segment. Contains either inline DATA lines or a STORED
pointer. ExtFields carry self-describing crypto parameters.

```
// <( ENCRYPTED WORD pbkdf:$argon2id$... cipher:aes-256-gcm-siv )>
// <( DATA <base64> )>
// <( DATA <base64> )>
// <( END WORD )>
```

### 4.3 STORED

A content-addressed storage pointer. The hash identifies the blob in
CAS. `keyw` is `"ct"` when the stored blob is ciphertext.

```
// <( STORED WORD sha3-256=<hexhash> )>
```

### 4.4 DATA

Base64-encoded ciphertext. Appears inside ENCRYPTED segments. Each
DATA line carries exactly 48 bytes of raw data (64 base64 characters).
The final line may be shorter.

### 4.5 CHAIN / CONFLICT

Chain anchors and conflict markers for the capability ledger.
Documented in `docs/spec/anchor-v1.md`.

### 4.6 IMMUTABLE / MUTABLE / MUTED

Integrity directives (no confidentiality transform):

```
// <( IMMUTABLE <name> sha3-256=<hexhash> )>
...content that must not change...
// <( MUTABLE <name> )>
```

MUTED is the sanitized form of an IMMUTABLE block — content replaced
by a hash pointer:

```
// <( MUTED <name> sha3-256=<hexhash> )>
```

### 4.7 KEY / CERT / UNKEY / UNCERT

Key/certified-key binding scopes:

```
// <( KEY <name> sha3-256=<hexhash> )>
...content signed under this key...
// <( UNKEY <name> )>

// <( CERT <name> sha3-256=<hexhash> )>
...content certified under this cert...
// <( UNCERT <name> )>
```

## 5. RSD Spec Vocabulary Aliases

The RSD spec (Ribose Standard RSD 12001) defines additional
vocabulary that enprot accepts as input-only aliases:

| RSD term      | enprot canonical |
|---------------|-----------------|
| CLASSIFY      | BEGIN           |
| UNCLASSIFY    | END             |
| CLASSIFIED    | ENCRYPTED       |
| SIGNED        | BEGIN           |
| SIGNATURE     | ENCRYPTED       |

The writer always emits the canonical enprot form.

## 6. ExtField Wire Format

ExtFields appear as space-separated `key:value` pairs inside the
directive line. Values are URL-encoded.

### Encrypted ExtFields

| Key        | Example value                              |
|------------|-------------------------------------------|
| pbkdf      | `$argon2id$v=19$m=65536,t=3,p=1$<salt>$`  |
| cipher     | `aes-256-gcm-siv`                          |
| recipient  | `<fingerprint>:<ml-kem-ciphertext-base64>`|

### Anchor ExtFields

| Key        | Example value                              |
|------------|-------------------------------------------|
| signer     | `<fingerprint>`                            |
| sig        | `<base64-signature>`                       |
| parents    | `<hex-hash>,<hex-hash>`                    |
| timestamp  | `<unix-seconds>`                           |

## 7. Round-Trip Semantics

All transforms are idempotent:

- **encrypt(BEGIN/END)** → ENCRYPTED with inline DATA
- **decrypt(ENCRYPTED)** → BEGIN/END with plaintext
- **store(BEGIN/END or ENCRYPTED)** → STORED pointer
- **fetch(STORED)** → original segment

Applying the same transform twice produces identical output.

## 8. Example Document

```
// Project configuration
// <( BEGIN database_url )>
postgres://localhost/myapp
// <( END database_url )>

// <( ENCRYPTED api_key pbkdf:$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$<hash> cipher:aes-256-gcm-siv )>
// <( DATA SGVsbG8gV29ybGQhIFRoaXMgaXMgZW5jcnlwdGVkIGRhdGEu )>
// <( END api_key )>

// <( IMMUTABLE license sha3-256=a1b2c3... )>
MIT License
// <( MUTABLE license )>
```
