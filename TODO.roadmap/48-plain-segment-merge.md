# 48 — Merge driver: plain-segment conflict handling

**Priority**: P2
**Status**: specified

## Problem

The merge driver (TODO.roadmap/43) walks ours positionally and emits
each Plain / Atom segment verbatim. This means conflicting Plain
edits on the theirs side are silently dropped — the user has no way
to know their non-EPT prose change was lost.

Example where this fails:

```
ancestor:    "intro\n// <( BEGIN X )>\nbody\n// <( END X )>\n"
ours:        "intro-our\n// <( BEGIN X )>\nbody\n// <( END X )>\n"
theirs:      "intro-their\n// <( BEGIN X )>\nbody\n// <( END X )>\n"
```

Both sides changed the same Plain line. The current driver keeps
ours verbatim, dropping the theirs edit. `git diff` after the merge
shows no conflict markers and the theirs edit is gone.

## Solution

When ours and theirs both modified a Plain segment that the ancestor
had, emit a `TextNode::Conflict` block under a reserved keyw
`__plain__`. The CONFLICT block carries both sides; the user runs
`enprot resolve` to pick.

The reserved keyw is double-underscored so it can never collide with
a real WORD (WORD identifiers are unqualified identifiers in host
languages; `__plain__` is reserved by convention across most
languages).

Detection strategy: hash each Plain segment in each side. If
ours_hash != theirs_hash AND both differ from base_hash, emit a
conflict.

## Acceptance criteria

- [ ] Conflicting Plain edits produce a `CONFLICT __plain__` block
      with both sides preserved
- [ ] Disjoint Plain edits (only one side changed) merge cleanly
- [ ] Identical Plain edits on both sides merge to a single copy
      (already works; preserve)
- [ ] Tests cover all four cases
