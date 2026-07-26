# 49 — Conflict lister

**Priority**: P2
**Status**: specified

## Problem

After a merge produces CONFLICT blocks, the only way to see how many
remain is to grep the file for `CONFLICT`. There's no structured
view that shows the WORDs in conflict, the size of each side, or
whether either side has a signature/cipher that would inform
resolution.

## Solution

New CLI subcommand:

```sh
enprot conflicts [--format text|json] FILE
```

Walks the parsed tree, finds every `TextNode::Conflict`, and emits
one summary line per conflict (text mode) or a JSON envelope (json
mode) — same envelope schema as TODO.roadmap/41.

Text output:

```
Agent_007    3 nodes ours / 4 nodes theirs
GEHEIM       1 nodes ours / 1 nodes theirs
__plain__    2 nodes ours / 2 nodes theirs
```

JSON output re-uses the `output::Envelope<ConflictsOutput>` shape
with `files: [{ path, conflicts: [{ word, ours_nodes, theirs_nodes }] }]`.

Exits non-zero if any conflicts are present (CI-friendly: drop into
`enprot conflicts` after a merge-driver step to gate the build).

## Acceptance criteria

- [ ] `enprot conflicts` lists every unresolved CONFLICT block
- [ ] Exit code is non-zero when conflicts exist
- [ ] `--format json` emits a versioned envelope
- [ ] Tests cover empty file, single-conflict file, multi-conflict file
