# 69 — Dry-run mode

**Priority**: P2 | **Status**: specified

## Problem
There's no way to preview what `enprot encrypt` would do without
actually modifying files. Users must either trust the command or
process to a temp file + diff.

## Design
- `--dry-run` flag on all transform subcommands (encrypt, decrypt,
  store, fetch, encrypt-store, passthrough).
- With `--dry-run`: parse + transform run as normal, but the output
  is written to stderr (not the file/pipe) with a summary of changes.
- Exit code: 0 if the operation would succeed, 1 if it would fail.
- No file I/O (no CAS writes, no output file creation).

## Out of scope
- Dry-run for verify/list/inspect (they already don't modify files).
- Dry-run for manifest/attest/scm (these create new files; dry-run
  for them is lower value).
