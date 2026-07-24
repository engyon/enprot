# Chain anchor DAG (Stage 1)

## Why

A linear chain (`block N+1 references block N`) doesn't merge. Two
parties appending simultaneously produce a fork with no canonical
resolution. A **DAG** of anchors — where each anchor declares zero or
more parents by hash — merges by union, exactly like git commits.

This unlocks the blockchain-in-a-file vision: each transformation is
attested in a tamper-evident, merge-friendly, capability-scoped
structure that lives inside the same text file as the content.

## Wire format

```
// <( CHAIN )>
// parents: 575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306 31560c26deba9a3678581853f828e3c1fafabf8ed48c10242162b872be8fdc0d
// signer:  ed25519:9f3a7b...
// timestamp: 2026-07-25T14:30:00Z
// mutations: encrypt WORD=Agent_007
// payload-hash: 7a4e9b...
// signature: 3045022100...
// <( END CHAIN )>
```

Fields:
- `parents`: zero or more SHA3-256 hashes of preceding anchors.
  Genesis anchor has zero parents. Merge anchor has 2+.
- `signer`: `<alg>:<key-fp>` (e.g., `ed25519:9f3a7b...`)
- `timestamp`: RFC 3339, optional
- `mutations`: human-readable description of what this anchor attests
  (e.g., `encrypt WORD=Agent_007`, `store WORD=GEHEIM`, `rotate
  WORD=X`). Informational only — not part of the signed payload.
- `payload-hash`: SHA3-256 of the canonical file-tree state at this
  anchor. This is what the signature commits to.
- `signature`: detached signature over `parents || signer || timestamp
  || payload-hash` with the named algorithm.

## Scope

1. New directive type `Command::Chain` in `etree::parse`
2. `TextNode::Chain { parents, signer, timestamp, mutations,
   payload_hash, signature }` variant
3. `src/ledger/` module:
   - `mod.rs` — public API: `anchor_for(paops, mutations) -> Anchor`,
     `verify_dag(anchors) -> Result<DagReport>`
   - `anchor.rs` — `Anchor` struct, serialization, signing/verification
   - `dag.rs` — `AnchorDag` adjacency structure, topological-walk
     verifier
4. `--anchor` flag on `encrypt`/`store`/`fetch`/`decrypt` (when the
   mutation is meaningful): produces a new anchor appended to the file
5. `--signer <key-file>` (repeatable): private keys to sign with
6. `--no-anchor` to skip anchoring when explicitly unwanted
7. `payload_hash` computation: Merkle root of all top-level segments
   (Stage 3 will deepen this; for Stage 1 it's a flat hash of segment
   hashes in order)

## Verification

`enprot verify-chain FILE`:
- Parses every `CHAIN` block in the file
- Builds the DAG
- For each anchor:
  - Recompute `payload-hash` from the file state at that anchor
    (snapshot mechanism TBD — for Stage 1, the anchor commits to the
    file *as it appears with that anchor included*)
  - Verify `signature` against `signer` pubkey
  - Check that every parent hash resolves to an anchor earlier in the
    file (no forward references)
- Report: total anchors, signer set, fork points, verification result

## Out of scope (deferred)

- Cross-file `INCLUDE` (Stage 3 / `TODO.finalize/25`)
- Snapshot mechanism for "file state at anchor X" (Stage 3 / Merkle)
- Timestamp authority integration (Stage 4a)
- Multi-sig anchors (signer field accepts one key for now)

## Acceptance criteria

- `--anchor` produces a parseable, verifiable `CHAIN` block
- `verify-chain` reports OK on a clean file, FAIL on tampering
- Tests: sign + verify round-trip; tampered payload fails; missing
  parent fails; fork (two anchors with same parent) accepts
- README + docs/ page explains the format

## Design constraints

- **OCP**: new signature algorithms are one variant in `SigAlgKind`
  (already true post-Ed25519); new mutation types are one variant
- **MECE**: chain anchors are distinct from encrypted/stored blocks;
  no overlap with existing directives
- **DRY**: signing/verification routes through `src/pki.rs`, not
  re-implemented
