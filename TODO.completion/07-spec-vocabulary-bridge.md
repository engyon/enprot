# 07 — Spec vocabulary bridge (CLASSIFY/UNCLASSIFY/CLASSIFIED as aliases)

**Priority**: P2
**Status**: specified

## Problem

The RSD spec uses classification-native vocabulary:

```
// <( CLASSIFY Deputies aes256siv )>
Confidential Source 13 is Mallory.
// <( UNCLASSIFY Deputies )>
```

enprot uses encryption-native vocabulary:

```
// <( BEGIN Deputies )>
Confidential Source 13 is Mallory.
// <( END Deputies )>
```

Plus the encrypted form:
- Spec: `CLASSIFIED Deputies aes256siv:base64=…`
- enprot: `ENCRYPTED Deputies pbkdf:… cipher:…`

Both are valid expressions of the same intent. The wire format
differs because enprot encodes more metadata (PHC string for KDF
parameters, structured cipher field).

## Solution

**Don't rename** — would break every existing EPT document. **Do
accept spec vocabulary as aliases** in the parser.

### Parser aliases

In `Directive::from_keyword`:

```rust
"CLASSIFY"     => Some(Directive::Begin),      // alias
"UNCLASSIFY"   => Some(Directive::End),        // alias
"CLASSIFIED"   => Some(Directive::Encrypted),  // alias
"SIGNED"       => Some(Directive::Begin),      // alias (signature intent)
"SIGNATURE"    => Some(Directive::Encrypted),  // alias (sig payload)
```

### Writer

`Directive::keyword()` stays as the canonical enprot form
(`BEGIN`/`END`/`ENCRYPTED`). The spec vocabulary is input-only.

### Intent markers

For `CLASSIFY`/`SIGNED` aliases, the parser records an `Intent`
flag on the resulting `BeginEnd` node:

```rust
pub enum BlockIntent {
    Generic,       // plain BEGIN/END
    Classify,      // CLASSIFY/UNCLASSIFY — confidentiality intent
    Signed,        // SIGNED/SIGNATURE — integrity intent
}
```

The transform layer uses the intent to pick defaults (e.g.,
SIGNED blocks default to no encryption, only signature).

## What this doesn't do

- Doesn't change the wire format on output. Existing files stay
  valid; new files use the canonical form.
- Doesn't unify the encrypted-block metadata. Spec's
  `aes256siv:base64=…` and enprot's `pbkdf:… cipher:…` carry
  different information; we keep enprot's richer form.

## Documentation

Add a "Spec vocabulary" section to the README showing the mapping.
This is the bridge for users coming from the RSD spec.

## Acceptance criteria

- [ ] Parser accepts CLASSIFY/UNCLASSIFY/CLASSIFIED/SIGNED/SIGNATURE
- [ ] `BlockIntent` enum added; intent recorded on parse
- [ ] Writer emits canonical enprot vocabulary (no change)
- [ ] README documents the alias mapping
- [ ] Tests: spec-form input round-trips through enprot

## Cross-references

- RSD spec §"Classified Blocks", §"Signed (integrity-protected) blocks"
- [[02-rsd-spec-conformance]]
