# 66 — CAS garbage collection

**Priority**: P2 | **Status**: specified

## Problem
CAS blobs accumulate. No GC command exists. Over time the CAS dir
grows unbounded with orphaned blobs no longer referenced by any EPT file.

## Design
- `enprot cas gc --casdir <DIR> [--root-files <FILES...>]` walks the
  CAS dir, identifies referenced hashes by parsing `--root-files`
  (and their transitive INCLUDE references), and deletes unreferenced
  blobs.
- Dry-run mode (`--dry-run`) prints what would be deleted.
- `--max-age <DURATION>` preserves blobs younger than the threshold
  (avoids deleting blobs mid-use by concurrent processes).

## Out of scope
- Remote CAS GC (backend-specific; covered by #27).
- CAS dedup across projects (separate concern).
