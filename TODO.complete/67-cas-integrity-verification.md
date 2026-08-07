# 67 — CAS integrity verification

**Priority**: P1 | **Status**: specified

## Problem
`enprot verify` checks file structure but not CAS integrity. Every
referenced STORED/INCLUDE hash should resolve to an existing blob
whose SHA3-256 matches the hash. Currently there's no command that
performs this end-to-end CAS check.

## Design
- `enprot cas verify --casdir <DIR> [--root-files <FILES...>]`
  parses each root file, collects all referenced hashes (STORED,
  INCLUDE, CHAIN payload), then verifies each exists in the CAS dir
  and the content hash matches.
- Output: one line per checked hash (OK/FAIL), summary at the end.
- `--format json` for machine consumption.

## Out of scope
- CAS repair (covered by #66 GC + re-store).
- Network CAS verification (backend-specific; #27).
