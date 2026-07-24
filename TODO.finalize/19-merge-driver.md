# WORD-region merge driver

## Why

Git's default textual merge works on lines. EPT files have semantic
structure — `BEGIN/END` regions, `STORED` pointers, `ENCRYPTED`
blocks — that line-based merge mangles. A custom driver parses both
sides as EPT, diffs at the WORD-region level, and produces either a
clean merge or a capability-aware conflict.

This is the lock-free distributed workflow's enabling feature.

## Scope

1. New subcommand `merge-driver`:
   - Implements the git merge-driver contract
   - `%O %A %B %P` are base, ours, theirs, path
   - Exit 0 on clean merge, 1 on conflict (leaves conflict markers)
2. `src/merge/` module:
   - `region.rs` — `WordRegion` type, file→region-list parser
   - `diff.rs` — 3-way diff at the region level
   - `conflict.rs` — conflict marker format, resolution options
3. `.gitattributes` snippet documented in README:
   ```
   *.ept merge=enprot diff=enprot
   ```
   Plus git config:
   ```
   [merge "enprot"]
       name = EPT WORD-region merge
       driver = enprot merge-driver %O %A %B %P
   ```
4. Conflict marker format (also EPT-valid):
   ```
   // <( CONFLICT Agent_007 )>
   // <( OURS )>
   ... our block ...
   // <( THEIRS )>
   ... their block ...
   // <( END CONFLICT )>
   ```
5. Merge semantics (formalized):
   - **Disjoint regions**: auto-merge
   - **Same region, identical content** (det AEAD matched): auto-merge
     to either side (they're equal)
   - **Same region, different content**: conflict marker
   - **Add on both sides**: insert in canonical order (alphabetical
     by WORD name, configurable)
   - **Delete vs. modify**: conflict (irreducible)
6. Tests: every merge case as a fixture triplet (base/ours/theirs)
   with expected merge result

## Out of scope

- Auto-resolution of capability conflicts (caller's job; see TODO 20)
- Structural merge (renesting, reordering children of a region) —
  always conflict
- Cross-file merge (Stage 3 INCLUDE)

## Acceptance criteria

- All fixture triplets merge correctly
- `merge-driver` integrates with git via documented `.gitattributes`
- README has a distributed-workflow cookbook section
- Performance: < 1s for files under 10k segments
