# 05 — IMMUTABLE / MUTABLE / MUTED blocks per RSD spec

**Priority**: P1
**Status**: specified (multi-week implementation; tracked here)

## Problem

The RSD spec §"Immutable Blocks and Binary Blobs" mandates a fourth
block type that enprot doesn't implement:

```
// <( IMMUTABLE Approved-May sha384=DC910F5E499F8BE84488D.. )>
(c) 2018 Ribose Inc. Any trade name used in this document …
// <( MUTABLE Approved-May )>
```

The semantics:
- `IMMUTABLE <name> <hashalg>=<hash>` — declares a block whose
  content is content-addressed. Parser verifies the hash matches.
- `MUTABLE <name>` — closes the IMMUTABLE block.
- `MUTED <name> <hashalg>=<hash>` — the block has been replaced by
  its hash reference (analogous to `STORED` for ciphertext). Used in
  sanitized distributions.

This is distinct from `ENCRYPTED`/`STORED`:
- IMMUTABLE provides **integrity** but no confidentiality.
- Useful for: license text, regulatory disclosures, standard
  references — content that must not change but isn't secret.

## Why it matters

enprot currently has no way to express "this static block must not
be modified". Users have to use ENCRYPTED with a known password,
which is awkward. IMMUTABLE/MUTABLE is the spec's answer.

The MERKLE tree (TODO.finalize/24) already exists for chain anchor
payload hashing; IMMUTABLE blocks integrate naturally — they're
Merkle leaves with a stable name.

## Solution

### Parser additions (`src/etree/parse.rs`)

Add `Immutable`, `Mutable`, `Muted` variants to `Directive` enum:

```rust
pub enum Directive {
    // ... existing variants ...
    Immutable,
    Mutable,
    Muted,
}
```

Add `TextNode::Immutable { name, hashalg, hash, txt }` and
`TextNode::Muted { name, hashalg, hash }` variants.

### Transform behavior

- **`verify`**: recompute the hash over `txt`, compare to declared
  `hash`. Fail on mismatch.
- **`store` (sanitize)**: replace IMMUTABLE/MUTABLE block with
  `MUTED <name> <hashalg>=<hash>`, content goes to CAS.
- **`fetch`**: restore IMMUTABLE/MUTABLE from CAS by hash.

### Hash algorithm

Spec uses `sha384`. enprot should support `sha3-256` (existing CAS
default) and `sha384` for spec conformance. The hash field carries
the algorithm name: `sha384=…`, `sha3-256=…`.

### Wire format

Per spec:
```
// <( IMMUTABLE <name> <hashalg>=<hex-hash> )>
... content ...
// <( MUTABLE <name> )>
```

Or muted:
```
// <( MUTED <name> <hashalg>=<hex-hash> )>
```

## Acceptance criteria

- [ ] `Directive::Immutable`, `Directive::Mutable`, `Directive::Muted` added
- [ ] `TextNode::Immutable`, `TextNode::Muted` added
- [ ] Parser recognizes the directives
- [ ] `verify` checks hash integrity
- [ ] `store` sanitizes IMMUTABLE → MUTED with CAS pointer
- [ ] `fetch` restores MUTED → IMMUTABLE from CAS
- [ ] Spec conformance test: round-trip a sample IMMUTABLE block
- [ ] Documentation in README

## Cross-references

- RSD spec: `../engyon/rsd-engyon-syntax/sections/04-syntax.adoc` §"Immutable Blocks and Binary Blobs"
- [[02-rsd-spec-conformance]]
- Existing `TextNode::Stored` is the closest analog (for ciphertext)
