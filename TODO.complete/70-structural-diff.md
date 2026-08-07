# 70 — Structural diff

**Priority**: P2 | **Status**: specified

## Problem
There's no way to see what changed between two EPT files at the
structural level. `diff` works on bytes but doesn't understand EPT
blocks — it can't say "WORD SECRET was encrypted in v1 but stored
in v2".

## Design
- `enprot diff <FILE_A> <FILE_B>` parses both files and shows
  structural differences: added/removed blocks, changed directives,
  changed extfields, changed CAS hashes.
- Output format: unified-diff-like, but at the EPT-node level.
- `--format json` for machine consumption.
- Uses the existing `scm::diff_manifests` logic for manifest-specific
  diffs, but generalizes to any EPT file.

## Out of scope
- Merge suggestion (covered by the merge driver + resolve).
- Byte-level diff (use `diff` for that).
- Semantic diff (which WORDs changed encryption).
