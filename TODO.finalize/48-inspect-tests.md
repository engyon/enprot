# 48 — Integration tests for `inspect` subcommand

**Priority**: P2
**Status**: done

## Problem

`enprot inspect` (TODO.finalize/42) emits a combined
structure/integrity/capability view but has no dedicated
integration test. Regression risk: a future change could break
its output format silently.

## Solution

Add `tests/cli/inspect.rs` covering:
- Basic file with WORD segments (BEGIN/END)
- File with ENCRYPTED block + cipher metadata
- File with chain anchor
- File with CONFLICT block (exit non-zero)
- `--format json` produces valid JSON envelope

## Acceptance criteria

- [x] `tests/cli/inspect.rs` exists
- [x] At least 4 test cases covering structure, integrity, conflicts
- [x] Tests assert on substring presence (don't pin to exact format)
- [x] `cargo test --test integration inspect` passes
