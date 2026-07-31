# EPT wire format — JSON Schema (v1)

**Status**: spec
**Schema version**: v1
**Stability**: stable — additive changes only within v1; bump to v2 for breaking changes.

This is the machine-readable companion to the prose spec in
[`docs/README.md`](../README.md) and the parser at
[`src/etree/parse.rs`](../../src/etree/parse.rs). Tools (validators,
LSP, third-party parsers, conformance suites) consume this schema
to reason about EPT files structurally.

## Top-level shape

An EPT file is a UTF-8 text file with a sequence of lines. Each line
is either **plain** (host-language content) or a **directive** (a
host-language comment that carries EPT metadata between configurable
separators).

The parsed representation — what this schema describes — is a tree
of blocks. The wire format itself is text; the schema describes the
AST that text parses to.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://engyon.org/schemas/ept-wire-format-v1.json",
  "title": "EPT file (v1)",
  "type": "object",
  "required": ["separators", "blocks"],
  "properties": {
    "separators": { "$ref": "#/$defs/Separators" },
    "blocks": {
      "type": "array",
      "items": { "$ref": "#/$defs/Block" }
    }
  },
  "$defs": {
    "Separators": {
      "type": "object",
      "required": ["left", "right", "comment_leader"],
      "properties": {
        "left": { "type": "string", "minLength": 1 },
        "right": { "type": "string", "minLength": 1 },
        "comment_leader": {
          "enum": ["//", "#", "--", "/*", ";"]
        }
      }
    },
    "Block": {
      "oneOf": [
        { "$ref": "#/$defs/PlainBlock" },
        { "$ref": "#/$defs/BeginEndBlock" },
        { "$ref": "#/$defs/EncryptedBlock" },
        { "$ref": "#/$defs/StoredBlock" },
        { "$ref": "#/$defs/ChainBlock" },
        { "$ref": "#/$defs/ImmutableBlock" },
        { "$ref": "#/$defs/MutedBlock" },
        { "$ref": "#/$defs/ConflictBlock" },
        { "$ref": "#/$defs/IncludeBlock" }
      ]
    },
    "PlainBlock": {
      "type": "object",
      "required": ["kind", "text"],
      "properties": {
        "kind": { "const": "plain" },
        "text": { "type": "string" }
      }
    },
    "BeginEndBlock": {
      "type": "object",
      "required": ["kind", "word"],
      "properties": {
        "kind": { "const": "begin_end" },
        "word": { "$ref": "#/$defs/Word" },
        "children": {
          "type": "array",
          "items": { "$ref": "#/$defs/Block" }
        }
      }
    },
    "EncryptedBlock": {
      "type": "object",
      "required": ["kind", "word", "extfields", "body"],
      "properties": {
        "kind": { "const": "encrypted" },
        "word": { "$ref": "#/$defs/Word" },
        "extfields": { "$ref": "extfield-schema-v1.json#/$defs/ExtfieldMap" },
        "body": {
          "oneOf": [
            { "$ref": "#/$defs/InlineData" },
            { "$ref": "#/$defs/StoredRef" }
          ]
        }
      }
    },
    "StoredBlock": {
      "type": "object",
      "required": ["kind", "word", "cas_key"],
      "properties": {
        "kind": { "const": "stored" },
        "word": { "$ref": "#/$defs/Word" },
        "cas_key": { "$ref": "#/$defs/CasKey" }
      }
    },
    "ChainBlock": {
      "type": "object",
      "required": ["kind", "extfields"],
      "properties": {
        "kind": { "const": "chain" },
        "extfields": {
          "type": "object",
          "required": ["index", "signer", "payload", "sig"],
          "properties": {
            "index": { "type": "integer", "minimum": 0 },
            "parents": {
              "type": "array",
              "items": { "$ref": "#/$defs/CasKey" }
            },
            "signer": { "type": "string", "pattern": "^[a-z0-9-]+:[a-f0-9]+$" },
            "ts": { "type": "string", "pattern": "^\\d{8}T\\d{6}Z$" },
            "payload": { "$ref": "#/$defs/CasKey" },
            "sig": { "type": "string", "pattern": "^[a-fA-F0-9]+$" },
            "mut": { "type": "string" }
          }
        }
      },
      "$comment": "See chain-anchor-v1.md for verification rules."
    },
    "ImmutableBlock": {
      "type": "object",
      "required": ["kind", "name", "hashalg", "hash", "text"],
      "properties": {
        "kind": { "const": "immutable" },
        "name": { "$ref": "#/$defs/Word" },
        "hashalg": { "enum": ["sha3-256", "sha3-512", "sha-256", "sha-512"] },
        "hash": { "type": "string", "pattern": "^[a-fA-F0-9]+$" },
        "text": { "type": "string" }
      }
    },
    "MutedBlock": {
      "type": "object",
      "required": ["kind", "name", "hashalg", "hash"],
      "properties": {
        "kind": { "const": "muted" },
        "name": { "$ref": "#/$defs/Word" },
        "hashalg": { "enum": ["sha3-256", "sha3-512", "sha-256", "sha-512"] },
        "hash": { "type": "string", "pattern": "^[a-fA-F0-9]+$" }
      }
    },
    "ConflictBlock": {
      "type": "object",
      "required": ["kind", "word", "ours", "theirs"],
      "properties": {
        "kind": { "const": "conflict" },
        "word": { "$ref": "#/$defs/Word" },
        "ours": {
          "type": "array",
          "items": { "$ref": "#/$defs/Block" }
        },
        "theirs": {
          "type": "array",
          "items": { "$ref": "#/$defs/Block" }
        }
      }
    },
    "IncludeBlock": {
      "type": "object",
      "required": ["kind", "hash"],
      "properties": {
        "kind": { "const": "include" },
        "hash": { "$ref": "#/$defs/CasKey" }
      }
    },
    "InlineData": {
      "type": "object",
      "required": ["kind", "chunks"],
      "properties": {
        "kind": { "const": "inline_data" },
        "chunks": {
          "type": "array",
          "items": { "type": "string", "pattern": "^[A-Za-z0-9+/=]*$" },
          "$comment": "Each chunk is at most 48 base64 characters; concatenation yields the ciphertext."
        }
      }
    },
    "StoredRef": {
      "type": "object",
      "required": ["kind", "cas_key"],
      "properties": {
        "kind": { "const": "stored_ref" },
        "cas_key": { "$ref": "#/$defs/CasKey" }
      }
    },
    "Word": {
      "type": "string",
      "pattern": "^[A-Z][A-Z0-9_]*$",
      "$comment": "Case-sensitive; convention is SCREAMING_SNAKE_CASE. Length 1-64."
    },
    "CasKey": {
      "type": "string",
      "pattern": "^[a-fA-F0-9]{32,128}$",
      "$comment": "SHA3-256 by default (64 hex chars); other hashes (sha-256, sha-512) explicitly prefixed in future revisions."
    }
  }
}
```

## Invariants the schema doesn't capture

The schema describes shape. The parser additionally enforces:

1. **BEGIN/END pairing.** Each `BEGIN WORD` has exactly one matching
   `END WORD` at the same nesting depth. Unmatched = parse error.
2. **Word scoping.** Nested `BEGIN WORD` with the same WORD is
   allowed but discouraged — the inner block shadows the outer for
   transform purposes.
3. **Extfield well-formedness.** See [`extfield-schema-v1.md`](extfield-schema-v1.md).
4. **Chain anchor signatures.** See [`chain-anchor-v1.md`](chain-anchor-v1.md).
5. **DATA chunk size.** Each DATA line carries at most 48 base64
   characters (36 bytes raw). The final chunk may be shorter.

These are documented in the linked specs and enforced by
`src/etree/parse.rs`. The schema is the shape contract; the parser
adds the semantic contract.

## Canonicalization

For hashing (CHAIN `payload`, IMMUTABLE `hash`, CAS keys):

1. Replace CRLF with LF.
2. UTF-8 normalize to NFC.
3. Strip trailing whitespace on each line.
4. Append a trailing LF if absent.

The canonical bytes are what's hashed. Non-canonical files parse
identically but produce different hashes — verifiers MUST canonicalize
before comparing.
