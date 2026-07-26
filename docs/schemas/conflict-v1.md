# EPT conflict block format — `conflict/v1`

When `enprot merge-driver` (TODO.roadmap/43) can't auto-resolve a
WORD region (both sides modified it differently), it emits a
CONFLICT block carrying both versions. The block is valid EPT —
the file remains parseable host-language source so `enprot list`,
`enprot verify`, and ordinary host-language tooling keep working
on a working tree with unresolved conflicts.

## Grammar (informal)

```
conflict-block := conflict-open ours-marker ours-content
                  theirs-marker theirs-content end-marker
conflict-open  := "// <( CONFLICT " word " )>" newline
ours-marker    := "// <( OURS )>" newline
theirs-marker  := "// <( THEIRS )>" newline
end-marker     := "// <( END " word " )>" newline
word           := WORD identifier (matches the opening keyw)
ours-content   := zero or more EPT nodes
theirs-content := zero or more EPT nodes
```

The opening keyword `CONFLICT` and the mode-switches `OURS` /
`THEIRS` are reserved EPT directives (see `Directive` enum in
`src/etree/mod.rs`). They cannot be used as WORD identifiers.

## Well-formedness

- The opening `CONFLICT <word>` must be immediately followed by
  `OURS` (no content between them).
- `OURS` must appear exactly once.
- `THEIRS` must appear exactly once, after `OURS`.
- The closing `END <word>` must match the opening `<word>`.

Malformed blocks produce a parse error pointing at the offending
line.

## Plain-segment conflicts

When both sides modify non-WORD content (e.g., the same prose
line), the merge driver (TODO.roadmap/48, when landed) emits a
conflict under the reserved keyw `__plain__`. The double-underscore
prefix reserves the name against collision with real WORD
identifiers.

## Resolution

`enprot resolve` (TODO.roadmap/44) walks CONFLICT blocks and
replaces each one with the caller-chosen side:

- `--ours` — keep `ours`, drop `theirs`
- `--theirs` — keep `theirs`, drop `ours`
- `--both` — concatenate both, in order
- `--skip` — drop both (data loss; opt-in)
- `--interactive` — prompt per conflict; requires a TTY

After resolve, the output contains zero CONFLICT blocks (or zero
of the resolved WORDs). Re-running resolve on a clean file is a
no-op.

## Example

Input file after a merge:

```
// <( BEGIN PUBLIC )>
hello world
// <( END PUBLIC )>
// <( CONFLICT Agent_007 )>
// <( OURS )>
// <( ENCRYPTED Agent_007 abc123… pbkdf:… )>
// <( THEIRS )>
// <( ENCRYPTED Agent_007 def456… pbkdf:… )>
// <( END Agent_007 )>
```

`enprot resolve --mode ours file.ept` produces:

```
// <( BEGIN PUBLIC )>
hello world
// <( END PUBLIC )>
// <( ENCRYPTED Agent_007 abc123… pbkdf:… )>
```

The CONFLICT markers are gone; the chosen side is preserved
verbatim.

## Forward compatibility

Unknown mode-switches inside a CONFLICT block (e.g., a future
`BASE` marker carrying the ancestor version) are ignored by
`v1` parsers and preserved verbatim through round-trips. A
`conflict/v2` consumer could use them; a `v1` consumer can't.
