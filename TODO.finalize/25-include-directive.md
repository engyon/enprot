# `INCLUDE` directive — cross-file DAG

## Why

Real projects split content across files: source modules,
documentation, configurations. Stage 3's Merkle tree is per-file; we
need cross-file references so a top-level manifest can attest to the
whole project.

`INCLUDE <hash>` lets one EPT file reference another by content hash.
A Merkle proof can then span files: prove that file F contains block
B, where F is referenced by manifest M, all the way up.

## Scope

1. New directive:
   ```
   // <( INCLUDE 575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306 )>
   ```
2. `INCLUDE` resolves through the CAS: the hash is a CAS blob ID,
   the blob is itself a serialized EPT file
3. `verify-chain` walks `INCLUDE` references recursively (with cycle
   detection)
4. `merkle` subcommand shows the cross-file DAG
5. Search path: `--include-path <dir>` (repeatable); CAS is always
   searched first
6. Cycle detection: BFS with visited-set; `Err` on cycle
7. Tests:
   - Single INCLUDE: parent + child files verify as one DAG
   - Diamond: A includes B and C, both include D — D verified once
   - Cycle: A includes B includes A — fails cleanly

## Out of scope

- HTTP/IPFS resolution of hashes (caller can implement via CAS
  backing store)
- Subtree privacy (proving a subtree without exposing siblings across
  files — future work, needs accumulator scheme)

## Acceptance criteria

- `verify-chain` walks INCLUDE references
- Diamond case verifies with no false-positive on tampered D
- Cycle detection works
- Docs page with multi-file project example
