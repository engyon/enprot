# 44 — Interactive conflict resolver

**Priority**: P2
**Status**: specified (consolidated from TODO.finalize/20)

## CLI

```sh
enprot resolve [--ours|--theirs|--both|--interactive] FILE
```

Walks CONFLICT blocks; for each: shows both sides, capability framing,
key fingerprint. Prompts: keep ours / theirs / both / re-encrypt /
skip.

## Acceptance criteria

- [ ] All four resolution modes produce valid EPT
- [ ] Interactive mode works from terminal (TTY check)
- [ ] CONFLICT markers always removed or replaced
