# Stage 3 — Merkle tree of WORD regions

## Why

Stage 1's `payload-hash` is a flat hash of segment hashes in order.
That's enough for chain anchor integrity, but it doesn't support:

- **Cross-file Merkle proofs**: prove block X is in file Y without
  revealing other blocks
- **Efficient incremental hashing**: re-hashing after one change is
  O(N); a tree makes it O(log N)
- **Selective disclosure**: prove a subtree without exposing siblings

A proper Merkle tree over the WORD-region structure gives us all
three.

## Scope

1. `src/merkle.rs`:
   - `MerkleTree { leaf_hashes, intermediate_hashes, root }`
   - `fn from_segments(segments: &[Segment]) -> MerkleTree`
   - `fn proof(&self, leaf_idx: usize) -> Result<MerkleProof>`
   - `fn verify_proof(root: Hash, leaf: Hash, proof: &MerkleProof) -> bool`
2. `WORD-region` becomes a `MerkleNode` recursively: each `BEGIN/END`
   pair's hash is computed over (children hashes + content hashes)
3. `enprot merkle FILE` subcommand prints the tree
4. Chain anchor's `payload-hash` becomes the Merkle root
5. Cross-file proofs: see TODO 25 (`INCLUDE`)

## Tree structure

```
file_root
├── plain-segment-1 (leaf)
├── WORD-Region-A (internal)
│   ├── child-segment-1 (leaf)
│   └── WORD-Region-A1 (internal)
│       └── child-segment-2 (leaf)
├── plain-segment-2 (leaf)
└── WORD-Region-B (internal)
    └── child-segment-3 (leaf)
```

Hash function: SHA3-256. Domain separation: prefix each hash input
with a byte tag (`0x00` for leaf, `0x01` for internal) to prevent
second-preimage attacks.

## Out of scope

- Cross-file proofs (TODO 25)
- Snapshotting at specific anchors (TODO 25 / INCLUDE)
- Persistent cache of Merkle roots (caller can cache)

## Acceptance criteria

- `merkle` subcommand prints a verifiable tree
- Anchor `payload-hash` matches the printed root
- Tampering any block changes the root
- Incremental update after single-block change is O(log N)
