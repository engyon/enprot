# 06 — KEY / CERT / UNKEY / UNCERT scoped declarations

**Priority**: P2
**Status**: specified

## Problem

The RSD spec §"Group keys" defines scoped key/cert declarations
inside the document:

```
// <( SIGNED ... )>
// <( KEY Deputies sha384=86716A025E4AAF0347C9.. )>
// <( CERT Alice sha384=7725AD485A8EBDE97BB04E86C1.. )>
  .. document body ..
// <( UNKEY Deputies )>
// <( UNCERT Alice )>
```

The semantics:
- `KEY <name> <hashalg>=<hash>` — declares a key by content hash.
  The hash references a NOC (Nereon configuration) key file in CAS.
- `CERT <name> <hashalg>=<hash>` — declares a public-key cert by
  content hash.
- `UNKEY <name>` / `UNCERT <name>` — end the scope, "forget" the
  binding.

Keys must be defined before use; they live inside a signed block at
the top of the document so the key bindings themselves are
integrity-protected.

## Why it matters

Currently enprot resolves keys via CLI flags (`-k WORD=password`) or
interactive prompts. There's no in-band way to declare "this WORD's
key is the content-addressed blob X". This blocks:

- Self-contained documents that carry their own key references
- Rotated keys within a single document
- Different keys for different sections (currently a single `-k` flag
  applies to one WORD)

## Solution

### Parser

Add `Directive::Key`, `Directive::Cert`, `Directive::Unkey`,
`Directive::Uncert`. These are scoping directives similar to
`Begin`/`End` but they affect a `KeyStore` rather than the text
stack.

### New module: `src/keystore.rs`

```rust
pub struct KeyBinding {
    pub name: String,
    pub kind: KeyKind,         // Symmetric | Public | Private
    pub hashalg: String,
    pub hash: String,          // CAS blob id
}

pub struct KeyStore {
    bindings: Vec<KeyBinding>, // ordered; later bindings shadow
}

impl KeyStore {
    pub fn lookup(&self, name: &str) -> Option<&KeyBinding>;
    pub fn resolve(&self, name: &str, casdir: &Path) -> Result<Vec<u8>>;
}
```

### Transform integration

`transform_encrypted` consults the `KeyStore` before falling back to
CLI-supplied passwords. If the WORD has a KEY binding, the binding's
CAS blob is loaded and used as the key material.

### Resolution

Keys are content-addressed. `resolve(name, casdir)`:
1. Look up binding by name.
2. Load CAS blob by hash.
3. Return bytes (NOC format or raw key material — implementation
   detail; spec leaves it open).

## Acceptance criteria

- [ ] `Directive::Key`, `Cert`, `Unkey`, `Uncert` added
- [ ] `src/keystore.rs` module with `KeyStore` API
- [ ] Parser populates KeyStore from in-band declarations
- [ ] `transform_encrypted` consults KeyStore before CLI passwords
- [ ] UNKEY/UNCERT correctly remove bindings from scope
- [ ] Tests: declare + use + undeclare round-trip
- [ ] Documentation

## Cross-references

- RSD spec: §"Group keys"
- [[02-rsd-spec-conformance]]
- [[05-immutable-mutable-blocks]] (similar parser pattern)
