# 72 — Progress reporting for large files

**Priority**: P3 | **Status**: specified

## Problem
For large files (100 MB+), enprot processes silently — no indication
of progress. Users don't know if it's hung or working.

## Design
- When stderr is a TTY, show a progress indicator:
  - Per-file: `Processing file 3/10: config.ept...`
  - Per-block (verbose): `  [WORD: SECRET] encrypting...`
- Use `indicatif` crate for spinners/progress bars.
- `--quiet` suppresses all progress output (existing behavior).
- `--no-progress` disables the indicator without quieting warnings.
- Non-TTY stderr: no indicator (avoid log noise in CI pipes).

## Out of scope
- Progress for network CAS operations (covered by async pipeline #54).
- Progress for benchmark runs (not user-facing).
