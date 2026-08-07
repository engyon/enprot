# 73 — Color output + terminal detection

**Priority**: P3 | **Status**: specified

## Problem
enprot's stdout/stderr output is plain text. For human-facing output
(inspect, list, verify-chain, conformance), colored highlighting
makes results easier to scan.

## Design
- Use `colored` or `nu-ansi-term` crate for colored output.
- Colors on stderr: warnings (yellow), errors (red), success (green).
- Colors on stdout: structural elements in inspect/list output
  (block types, WORD names, hash prefixes).
- `--no-color` flag + `$NO_COLOR` env var override.
- Terminal detection: colors only when stdout/stderr is a TTY.
- Respects the `NO_COLOR` de-facto standard (https://no-color.org/).

## Out of scope
- Colors in JSON output (JSON is machine-consumed; colors would
  break parsers).
- Terminal width detection (use existing wrapping).
- Custom color themes.
