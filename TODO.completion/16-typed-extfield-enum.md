# 16 — Typed extfield enum (replace stringly-typed BTreeMap)

**Priority**: P2
**Status**: done (typed view); wire-format refactor tracked here

## Problem

Chain anchors and Encrypted blocks carry extfields as
`BTreeMap<String, String>`:

```rust
pub enum TextNode {
    Encrypted {
        keyw: String,
        txt: TextTree,
        extfields: BTreeMap<String, String>,
    },
    Chain { extfields: BTreeMap<String, String> },
    // ...
}
```

`src/extfield.rs` provides typed accessors (`EncryptedExtFields`,
`AnchorExtFields`) — zero-cost borrowed views. Good for reads.

**Writes still go through the string map.** A new caller building a
chain anchor must remember field names: `signer`, `sig`, `payload`,
`parents`, `ts`, `mut`. Typos produce silent failures (the field is
written but never read). The wire format is correct by accident,
not by construction.

## Solution

Add a typed enum that owns the wire representation:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptedExtField {
    Pbkdf(String),         // PHC-encoded
    Cipher(String),        // cipher:$alg$iv=...
    Recipients(Vec<String>), // comma-sep fingerprints
    RecipientCt { fp: String, ct: String },
    Attribute(String),     // ABAC predicate (URL-encoded)
    // Forward-compat: unknown fields preserved verbatim.
    Unknown { key: String, value: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorExtField {
    Signer(String),
    Sig(String),
    Signers(Vec<String>),
    Sigs(Vec<String>),
    Payload(String),
    Parents(Vec<String>),
    Timestamp(String),
    Mutation(String),
    Unknown { key: String, value: String },
}
```

### Wire format (unchanged)

`EncryptedExtField::Pbkdf(s)` serializes to `pbkdf:s` in the
`BTreeMap<String, String>`. The BTreeMap remains the wire format;
the enum is the in-memory type-safe representation.

### Constructors

```rust
impl EncryptedExtField {
    pub fn into_entry(self) -> (String, String) { ... }
    pub fn from_entry(k: &str, v: &str) -> Result<Self> { ... }
}
```

### Call sites

```rust
// Old:
let mut ef = BTreeMap::new();
ef.insert("signer".to_string(), signer_fp.clone());
ef.insert("sig".to_string(), hex_sig.clone());

// New:
let ef: Vec<AnchorExtField> = vec![
    AnchorExtField::Signer(signer_fp.clone()),
    AnchorExtField::Sig(hex_sig.clone()),
];
let wire: BTreeMap<String, String> = ef.iter()
    .map(|f| f.clone().into_entry())
    .collect();
```

More verbose but type-safe. The compiler rejects typos.

### Migration

- Keep `EncryptedExtFields`/`AnchorExtFields` (zero-cost readers) — they read
  from BTreeMap.
- Add `EncryptedExtField`/`AnchorExtField` enums (owned, write-side).
- Call sites migrate incrementally. Old code still works.

## Acceptance criteria

- [x] Enum design specified
- [ ] `EncryptedExtField` and `AnchorExtField` enums added
- [ ] `into_entry()` / `from_entry()` round-trip
- [ ] At least one call site (anchor builder) migrated to the enum
- [ ] Tests: typo'd field names caught at compile time
- [ ] Documentation: when to use enum vs zero-cost reader

## Cross-references

- TODO.finalize/46 — original typed-extfield work (zero-cost reader)
- [[10-capability-threshold-provenance]] — adds new extfield variants
