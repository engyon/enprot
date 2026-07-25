# 43 — WORD-region merge driver

**Priority**: P2
**Status**: specified (consolidated from TODO.finalize/19)

## Wire format

```
// <( CONFLICT Agent_007 )>
// <( OURS )>     capability: Decryptor-Agent_007, key-fp 0xABCD…
... block …
// <( THEIRS )>   capability: Decryptor-Agent_007, key-fp 0x1234…
... block …
// <( END CONFLICT )>
```

## Implementation

- `src/merge/` module: region diff, conflict marker format
- `enprot merge-driver %O %A %B %P` (git merge-driver contract)
- `.gitattributes`: `*.ept merge=enprot`
- CONFLICT directive parser (using reserved `Directive::Conflict`)

## Acceptance criteria

- [ ] Disjoint regions auto-merge
- [ ] Same WORD different content → conflict markers
- [ ] Conflict markers are valid EPT (re-parseable)
