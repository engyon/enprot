# 47 — Manifest format specification

**Priority**: P1
**Status**: specified

## Problem

The provenance manifest (TODO.roadmap/51) and supply-chain manifest
(TODO.roadmap/52) share a wire format built from existing EPT
directives plus two informal conventions:

- `# path: <relative-path>` precedes each per-file INCLUDE
- `# dep: <name>=<version>` precedes each per-dependency INCLUDE

These conventions live only in code comments and tests; there's no
authoritative spec a third-party implementer can reference. A
customer verifying a manifest can't tell from the format alone
whether a `# path:` comment is required to precede INCLUDE, whether
the path is relative or absolute, or what the canonical sort order
is.

## Solution

Promote the format to a first-class spec under `docs/schemas/`,
alongside the JSON output schema (TODO.roadmap/41). The spec covers:

- Grammar (informal BNF)
- Path canonicalisation rules (POSIX-normalised, relative to the
  manifest's own directory)
- Sort order (lexicographic by label, deps before paths when both
  present)
- Forward-compatibility: unknown `# foo:` comments are preserved
  by parsers but ignored by verifiers
- Conflict semantics: a manifest with two INCLUDE lines for the
  same `# path:` label is malformed and `verify` must reject it

## File layout

```
docs/schemas/
├── enprot-v1.md          (existing — JSON output schema)
├── manifest-v1.md        (new — this spec)
└── conflict-v1.md        (new — CONFLICT block wire format)
```

## Acceptance criteria

- [ ] `docs/schemas/manifest-v1.md` exists and covers every field
      the parser recognises
- [ ] `docs/schemas/conflict-v1.md` documents the CONFLICT/OURS/
      THEIRS/END format added in TODO.roadmap/43
- [ ] Round-trip example: a sample manifest parses, re-serializes
      byte-identically, and verifies under a sample builder key
