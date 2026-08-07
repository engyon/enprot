# 30 — RSD conformance suite: expand coverage

**Priority**: P1
**Status**: specified

## Problem

`tests/rsd-conformance/` ships 5 fixture files covering the core EPT
markup surface (BEGIN/END/ENCRYPTED/STORED/DATA + plain text). Each
fixture asserts a specific parse + transform behavior. The suite
catches regressions in the **core** surface but misses:

- **CHAIN anchor format** — 0 conformance tests for the chain-anchor DAG (signer fingerprints, payload hashes, parent links).
- **IMMUTABLE / MUTED directives** — 0 tests for the RSD content-immutability features.
- **Capability extfields** (`recipient:`, `key:`, `cert:`) — 0 tests for the capability surface.
- **Conflict markers** — 0 tests for the merge-driver CONFLICT block format.
- **Include directives** — 0 tests for the `INCLUDE <hash>` provenance manifest format.
- **Edge cases** in existing surfaces — malformed DATA lines, unterminated blocks, nested BEGIN/END, etc.

The RSD (Ribose Standard for EPT) is the **single source of truth**
for behavior. Without conformance coverage, "what's correct?" is
implicit and easy to break.

## Goals

- Expand from 5 to ~25 fixtures covering every EPT directive.
- Each fixture has:
  - Input file (`*.ept`).
  - Expected canonical-parse output (`*.tree` — the `list` output).
  - Expected transform output for each applicable operation (`*.store`, `*.fetch`, `*.encrypt`, `*.decrypt`).
  - A `meta.toml` describing what the fixture exercises.
- CI runs the full conformance suite on every PR.
- Adding a fixture is a 1-file change (drop in `tests/rsd-conformance/<name>/`).

## Design

### Directory layout

```
tests/rsd-conformance/
├── 01-basic-begin-end/
│   ├── input.ept
│   ├── expected.tree         # output of `enprot list`
│   ├── expected.store        # output of `enprot store`
│   ├── expected.fetch        # output of `enprot fetch` after store
│   ├── meta.toml             # fixture metadata
│   └── README.md             # what this tests
├── 02-encrypted-inline-data/
│   └── ...
├── 03-stored-cas-pointer/
│   └── ...
├── ... (existing 5 + new 20) ...
└── run_all.rs                # the test driver — walks dirs, runs each fixture
```

### Fixture metadata (`meta.toml`)

```toml
name = "10-chain-anchor-linear"
description = "Three CHAIN anchors forming a linear chain. Verifies parent linkage and payload hash stability."
directives = ["CHAIN"]
operations = ["verify-chain"]
tags = ["chain", "anchor"]
```

The driver (`run_all.rs`) reads each `meta.toml`, runs the operations
listed, and asserts the actual output equals the expected file.
Missing expected files mean "operation not applicable" — the driver
skips.

### New fixtures to add

| # | Name | Directives exercised |
|---|---|---|
| 06 | `chain-anchor-linear` | CHAIN (3-anchor linear chain) |
| 07 | `chain-anchor-merge` | CHAIN (2-parent merge anchor) |
| 08 | `chain-anchor-genesis` | CHAIN (single anchor, no parents) |
| 09 | `immutable-content` | IMMUTABLE + content hash |
| 10 | `muted-sanitized` | MUTED + CAS reference |
| 11 | `conflict-three-way` | CONFLICT markers from merge driver |
| 12 | `include-manifest` | INCLUDE (provenance manifest) |
| 13 | `recipient-key-declaration` | KEY/UNKEY/CERT/UNCERT |
| 14 | `nested-begin-end` | BEGIN/END with depth-3 nesting |
| 15 | `multiple-words-same-file` | multiple WORDs in one file |
| 16 | `encrypted-stored-ciphertext` | ENCRYPTED + STORED (ct in CAS) |
| 17 | `encrypted-inline-ciphertext` | ENCRYPTED + DATA (ct inline) |
| 18 | `multiline-data-base64` | DATA across 4+ lines |
| 19 | `malformed-unterminated-block` | parse error case |
| 20 | `malformed-bad-extfield` | parse error case (bad cipher= value) |
| 21 | `empty-file` | edge case |
| 22 | `stdin-passthrough` | no EPT markup, no transformation |
| 23 | `encrypted-with-recipient-extfield` | recipient-key encrypt |
| 24 | `capability-policy-violation` | encrypt denied by policy |
| 25 | `custom-separators` | non-default `// <( ... )>` |

### Driver enhancements

The existing driver in `tests/rsd-conformance/run_all.rs` (post-#219)
loops over `tests/rsd-conformance/*/`. Extend it to:

1. Read `meta.toml` to learn which operations apply.
2. For each operation, run the corresponding `enprot` subcommand
   with the fixture's input.
3. Diff actual vs expected.
4. On mismatch: print a unified diff and the fixture path; fail.

For parse-error fixtures, the expected file is `expected.stderr`
instead of `expected.tree`.

## Implementation plan

1. Land the 20 new fixture directories. Each is a self-contained
   commit (input + expected + meta + README).
2. Extend the driver to honor `meta.toml` and pick operations from
   the `operations` array.
3. Add `expected.stderr` support for negative fixtures.
4. Document fixture-authoring in `tests/rsd-conformance/README.md`.
5. Add CI step to run the full conformance suite.

## Test plan

- [ ] All 25 fixtures pass locally.
- [ ] Each fixture has a `meta.toml` with at least `name` + `description`.
- [ ] At least one fixture per EPT directive (CHANGELOG: audit).
- [ ] At least one negative fixture (parse error).
- [ ] CI runs the suite on every PR.

## Out of scope

- Differential testing against a second implementation (none exists).
- Property-based fuzzing of the parser (covered by `proptest_invariants`).
- Localization of error messages in expected output.
