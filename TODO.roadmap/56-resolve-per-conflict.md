# 56 — Resolve: per-conflict overrides

**Priority**: P2
**Status**: specified

## Problem

`enprot resolve` (TODO.roadmap/44) applies one mode (`--ours`,
`--theirs`, `--both`, `--skip`) to every CONFLICT block in the file.
Real merge scenarios often need per-WORD resolution: keep ours for
`Agent_007`, take theirs for `GEHEIM`, both for `PUBLIC`.

Today the only way to do this is to run resolve N times with
different modes — but each run resolves ALL conflicts, so the
workflow is "manually edit the file between resolve calls". That's
hostile to scripting.

## Solution

Extend `ResolveSubcmd` with a `--word WORD:MODE` repeatable flag:

```sh
enprot resolve \
  --word Agent_007:ours \
  --word GEHEIM:theirs \
  --word PUBLIC:both \
  FILE
```

The flag is repeatable. Conflicts on WORDs not listed fall back to
the global `--mode` (default `interactive`, or `--mode skip` for
non-interactive CI runs).

Precedence: explicit `--word WORD:MODE` wins over `--mode`.

## Acceptance criteria

- [ ] `--word WORD:MODE` resolves that WORD with the chosen mode
- [ ] Conflicts on unlisted WORDs fall back to `--mode`
- [ ] Unknown WORDs in `--word` are silently ignored (not an error;
      the file may have changed between conflicts listing and resolve)
- [ ] Tests cover mixed-mode resolution
