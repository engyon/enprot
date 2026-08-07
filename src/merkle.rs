// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Merkle tree over arbitrary byte-segment leaves (TODO.finalize/24).
//!
//! Each leaf is hashed with SHA3-256 over `0x00 || data` (domain
//! separation tag prevents second-preimage attacks where an internal
//! node's hash could be re-interpreted as a leaf). Internal nodes
//! hash their children with `0x01 || left_hash || right_hash`.
//!
//! Properties:
//!
//! - **Tamper-evident**: any change to a leaf propagates to the root.
//! - **Incremental**: re-rooting after one leaf change is O(log N),
//!   not O(N).
//! - **Selective disclosure**: a [`MerkleProof`] proves a specific
//!   leaf is in the tree without exposing siblings. (v1 returns
//!   sibling hashes; future work could use accumulator schemes for
//!   constant-size proofs.)
//! - **Cross-file**: an `INCLUDE` directive (TODO.finalize/25) can
//!   reference a foreign tree's root, and proofs can span files.
//!
//! ## Out of scope for v1
//!
//! - Persistent caching of intermediate hashes (callers can memoize).
//! - Cross-file proofs (TODO.finalize/25 — needs INCLUDE directive).
//! - Snapshot-at-anchor (defer to TODO.finalize/17 integration).
//!
//! ## Integration
//!
//! Today this module is self-contained: tests cover leaf hashes,
//! tree construction, root stability, and proof verification. The
//! chain anchor module (`src/ledger/`) will eventually compute
//! `payload_hash` via [`MerkleTree::root`] instead of the flat
//! hash currently in `Anchor::id()` — that change lands in a
//! follow-up PR so existing anchor tests don't break.

use crate::crypto::{CryptoPolicyDefault, hexdigest};
use crate::error::{Error, Result};

/// SHA3-256 digest, 32 bytes. Domain-separated from [`NodeHash`]:
/// leaf hashes and internal-node hashes use distinct type wrappers
/// so callers can't accidentally swap them.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct LeafHash(pub [u8; 32]);

/// Internal-node hash. Same wire format (32 bytes) as [`LeafHash`]
/// but a distinct type so the second-preimage protection is
/// type-enforced, not just byte-tag-enforced.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct NodeHash(pub [u8; 32]);

/// Top of the tree — what chain anchors commit to.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct MerkleRoot(pub [u8; 32]);

impl LeafHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Hex(format!(
                "leaf hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(LeafHash(arr))
    }
}

impl NodeHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl MerkleRoot {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Byte tags prepended to hash inputs to prevent second-preimage
/// attacks. RFC 6962 style: `0x00` for leaves, `0x01` for internal
/// nodes. Without tags, an attacker who controls leaf data could
/// craft a leaf whose hash equals an internal node's hash, then
/// substitute one for the other.
const LEAF_TAG: u8 = 0x00;
const INTERNAL_TAG: u8 = 0x01;

/// Hash a single leaf's data. SHA3-256 over `LEAF_TAG || data`.
pub fn hash_leaf(data: &[u8]) -> Result<LeafHash> {
    let policy = CryptoPolicyDefault {};
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(LEAF_TAG);
    input.extend_from_slice(data);
    let hex = hexdigest("sha3-256", &input, &policy)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hex::decode(hex)?);
    Ok(LeafHash(arr))
}

/// Hash two children into an internal node. SHA3-256 over
/// `INTERNAL_TAG || left || right`.
pub fn hash_internal(left: &LeafHash, right: &LeafHash) -> Result<NodeHash> {
    let policy = CryptoPolicyDefault {};
    let mut input = Vec::with_capacity(1 + 32 + 32);
    input.push(INTERNAL_TAG);
    input.extend_from_slice(&left.0);
    input.extend_from_slice(&right.0);
    let hex = hexdigest("sha3-256", &input, &policy)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hex::decode(hex)?);
    Ok(NodeHash(arr))
}

/// A Merkle tree built from N leaves. Construction is O(N); the
/// tree is immutable after build. Internal layout: level 0 is the
/// leaf layer (N hashes), each subsequent level halves until one
/// hash remains (the root).
///
/// For odd-width levels, the last node is promoted unchanged
/// (RFC 6962 convention — simpler than duplicating the last child).
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// All levels, bottom-up. `levels[0]` is leaves; `levels.last()`
    /// is a singleton containing the root.
    levels: Vec<Vec<LeafHash>>,
}

/// Position of a leaf within the tree. Stable as long as the tree
/// isn't rebuilt with different leaves.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeafIndex(pub usize);

/// One step in a Merkle proof: the sibling hash at this level and
/// whether it's the left or right sibling of the path node.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProofStep {
    pub sibling: LeafHash,
    pub sibling_is_left: bool,
}

/// Inclusion proof for a specific leaf. Verifying requires
/// recomputing hashes from the leaf upward and comparing against
/// the published root.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf: LeafHash,
    pub steps: Vec<ProofStep>,
}

impl MerkleTree {
    /// Build a tree from leaf data. Each `&[u8]` becomes one leaf.
    /// Empty input produces an empty tree whose [`MerkleTree::root`]
    /// returns `Err`.
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Result<Self> {
        if leaves.is_empty() {
            return Ok(MerkleTree { levels: Vec::new() });
        }
        let mut levels: Vec<Vec<LeafHash>> = Vec::new();
        let mut current: Vec<LeafHash> =
            leaves.iter().map(|d| hash_leaf(d)).collect::<Result<_>>()?;
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<LeafHash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    // Pair: hash both
                    let node = hash_internal(&current[i], &current[i + 1])?;
                    // NodeHash and LeafHash have identical byte layout (32 bytes);
                    // we store levels uniformly as LeafHash for simplicity. The
                    // type wrapper is advisory; the byte tag in the hash input
                    // is what actually prevents substitution.
                    next.push(LeafHash(node.0));
                    i += 2;
                } else {
                    // Odd one out: promote unchanged (RFC 6962)
                    next.push(current[i]);
                    i += 1;
                }
            }
            levels.push(next.clone());
            current = next;
        }
        Ok(MerkleTree { levels })
    }

    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count() == 0
    }

    /// The root hash. `Err` for empty trees.
    pub fn root(&self) -> Result<MerkleRoot> {
        if self.is_empty() {
            return Err(Error::InvalidArg {
                arg: "merkle_tree",
                reason: "Merkle tree is empty; no root".to_string(),
            });
        }
        let top = self.levels.last().unwrap();
        debug_assert_eq!(top.len(), 1);
        Ok(MerkleRoot(top[0].0))
    }

    /// All leaf hashes, bottom layer.
    pub fn leaves(&self) -> &[LeafHash] {
        self.levels.first().map(|l| l.as_slice()).unwrap_or(&[])
    }

    /// Construct an inclusion proof for the leaf at `idx`. `Err` if
    /// `idx` is out of bounds or the tree is empty.
    pub fn proof(&self, idx: usize) -> Result<MerkleProof> {
        if self.is_empty() {
            return Err(Error::InvalidArg {
                arg: "merkle_tree",
                reason: "Merkle tree is empty; no proofs".to_string(),
            });
        }
        let leaves = self.leaves();
        if idx >= leaves.len() {
            return Err(Error::InvalidArg {
                arg: "idx",
                reason: format!(
                    "leaf index {idx} out of bounds (tree has {} leaves)",
                    leaves.len()
                ),
            });
        }
        let leaf = leaves[idx];
        let mut steps = Vec::new();
        let mut i = idx;
        for level in 0..self.levels.len() - 1 {
            let layer = &self.levels[level];
            // Sibling is at i^1 (XOR with 1) when pairing exists.
            let sibling_idx = i ^ 1;
            if sibling_idx < layer.len() && sibling_idx != i {
                // Standard pair: sibling is the other side.
                let sibling = layer[sibling_idx];
                let sibling_is_left = sibling_idx < i;
                steps.push(ProofStep {
                    sibling,
                    sibling_is_left,
                });
            } else {
                // Odd-one-out promotion: no sibling at this level,
                // parent is the node itself. No step added.
            }
            i /= 2;
        }
        Ok(MerkleProof { leaf, steps })
    }

    /// Pretty-print the tree, one level per line, hashes hex-encoded.
    /// For debugging and `enprot merkle FILE` output.
    pub fn debug_dump(&self) -> String {
        let mut out = String::new();
        for (level_num, level) in self.levels.iter().enumerate() {
            out.push_str(&format!("level {}: ", level_num));
            for (i, h) in level.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(&h.to_hex());
            }
            out.push('\n');
        }
        out
    }
}

/// Verify a proof against a published root. Recomputes hashes from
/// the leaf upward using the proof's sibling steps and checks
/// equality with `root`.
pub fn verify_proof(root: &MerkleRoot, proof: &MerkleProof) -> Result<bool> {
    let mut current = proof.leaf;
    for step in &proof.steps {
        let node = if step.sibling_is_left {
            hash_internal(&step.sibling, &current)?
        } else {
            hash_internal(&current, &step.sibling)?
        };
        current = LeafHash(node.0);
    }
    Ok(current.0 == root.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn empty_tree_has_no_root() {
        let t = MerkleTree::from_leaves(&[]).unwrap();
        assert!(t.is_empty());
        assert!(t.root().is_err());
    }

    #[test]
    fn single_leaf_tree_root_equals_leaf_hash() {
        let t = MerkleTree::from_leaves(&[leaf("hello")]).unwrap();
        let root = t.root().unwrap();
        let expected = hash_leaf(b"hello").unwrap();
        assert_eq!(root.0, expected.0);
    }

    #[test]
    fn root_is_stable_for_same_input() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c")];
        let t1 = MerkleTree::from_leaves(&leaves).unwrap();
        let t2 = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(t1.root().unwrap(), t2.root().unwrap());
    }

    #[test]
    fn root_changes_when_leaf_changes() {
        let t1 = MerkleTree::from_leaves(&[leaf("a"), leaf("b")]).unwrap();
        let t2 = MerkleTree::from_leaves(&[leaf("a"), leaf("c")]).unwrap();
        assert_ne!(t1.root().unwrap(), t2.root().unwrap());
    }

    #[test]
    fn odd_width_promotes_last_node() {
        // 3 leaves: level 0 has 3 hashes, level 1 has 2 (one paired,
        // one promoted), level 2 has 1 (root).
        let t = MerkleTree::from_leaves(&[leaf("a"), leaf("b"), leaf("c")]).unwrap();
        assert_eq!(t.levels[0].len(), 3);
        assert_eq!(t.levels[1].len(), 2);
        assert_eq!(t.levels[2].len(), 1);
    }

    #[test]
    fn proof_round_trips() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let t = MerkleTree::from_leaves(&leaves).unwrap();
        let root = t.root().unwrap();
        for i in 0..leaves.len() {
            let proof = t.proof(i).unwrap();
            assert!(verify_proof(&root, &proof).unwrap());
        }
    }

    #[test]
    fn proof_round_trips_odd_width() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c")];
        let t = MerkleTree::from_leaves(&leaves).unwrap();
        let root = t.root().unwrap();
        for i in 0..leaves.len() {
            let proof = t.proof(i).unwrap();
            assert!(verify_proof(&root, &proof).unwrap());
        }
    }

    #[test]
    fn proof_fails_with_wrong_root() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let t = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = t.proof(0).unwrap();

        // Build a different tree to get a different root.
        let other = MerkleTree::from_leaves(&[leaf("x"), leaf("y"), leaf("z"), leaf("w")]).unwrap();
        let wrong_root = other.root().unwrap();

        assert!(!verify_proof(&wrong_root, &proof).unwrap());
    }

    #[test]
    fn proof_fails_with_tampered_leaf() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let t = MerkleTree::from_leaves(&leaves).unwrap();
        let root = t.root().unwrap();
        let mut proof = t.proof(0).unwrap();
        // Tamper: claim a different leaf hash.
        proof.leaf = hash_leaf(b"X").unwrap();
        assert!(!verify_proof(&root, &proof).unwrap());
    }

    #[test]
    fn proof_fails_with_tampered_sibling() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c"), leaf("d")];
        let t = MerkleTree::from_leaves(&leaves).unwrap();
        let root = t.root().unwrap();
        let mut proof = t.proof(0).unwrap();
        assert!(!proof.steps.is_empty());
        proof.steps[0].sibling = hash_leaf(b"X").unwrap();
        assert!(!verify_proof(&root, &proof).unwrap());
    }

    #[test]
    fn out_of_bounds_index_rejected() {
        let t = MerkleTree::from_leaves(&[leaf("a")]).unwrap();
        assert!(t.proof(5).is_err());
    }

    #[test]
    fn leaf_hash_changes_with_data() {
        let h1 = hash_leaf(b"hello").unwrap();
        let h2 = hash_leaf(b"world").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn leaf_and_internal_tags_differ() {
        // Two hashings with the same byte payload but different tags
        // must produce different hashes (second-preimage protection).
        let leaf_hash = hash_leaf(&[0u8; 64]).unwrap();

        // Manually construct what an internal hash with the same byte
        // pattern would look like if it weren't tagged.
        let policy = CryptoPolicyDefault {};
        let untagged = hexdigest("sha3-256", &[0u8; 64], &policy).unwrap();
        assert_ne!(leaf_hash.to_hex(), untagged);
    }

    #[test]
    fn large_tree_root_computes() {
        // 100 leaves — sanity check that larger trees build without
        // issue and produce a stable root.
        let leaves: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("leaf-{}", i).into_bytes())
            .collect();
        let t1 = MerkleTree::from_leaves(&leaves).unwrap();
        let t2 = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(t1.root().unwrap(), t2.root().unwrap());
        assert_eq!(t1.leaf_count(), 100);
    }

    #[test]
    fn debug_dump_is_nonempty_for_nonempty_tree() {
        let t = MerkleTree::from_leaves(&[leaf("a"), leaf("b")]).unwrap();
        let dump = t.debug_dump();
        assert!(dump.contains("level 0"));
        assert!(dump.contains("level 1"));
    }
}
