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

//! [`AnchorDag`] — adjacency structure over [`SignedAnchor`]s with
//! parent resolution and validation.
//!
//! A DAG is constructed by pushing anchors in the order they appear
//! in a file. The structure detects:
//!
//! - Duplicate anchor IDs
//! - Forward references (anchor references a parent not yet seen)
//! - Cycles (anchor references itself transitively)
//! - Missing genesis (every parent chain must terminate at a
//!   zero-parent anchor)
//!
//! Verification (signature checks against pubkeys) is a separate
//! concern; see [`AnchorDag::verify_signatures`].

use std::collections::{HashMap, HashSet};

use crate::error::Error;

use super::anchor::{AnchorHash, SignedAnchor};

/// A validated DAG of chain anchors. Construction is fallible —
/// invalid input (forward refs, cycles, duplicates) returns [`DagError`].
#[derive(Debug, Default)]
pub struct AnchorDag {
    /// Insertion order — preserves history for streaming audits.
    order: Vec<AnchorHash>,
    /// Hash → anchor.
    by_id: HashMap<AnchorHash, SignedAnchor>,
}

/// Per-anchor verification result.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AnchorReport {
    pub id: AnchorHash,
    pub parents: Vec<AnchorHash>,
    pub ok: bool,
    /// Set when `ok == false`; human-readable reason.
    pub error: Option<String>,
}

/// Whole-DAG verification summary.
#[derive(Debug, Clone)]
pub struct DagReport {
    pub anchors_total: usize,
    pub reports: Vec<AnchorReport>,
    /// Anchor IDs that have no children (the "tips" of the DAG).
    /// Multiple tips mean a fork — verifiers report this so callers
    /// can decide whether to merge or investigate.
    pub tips: Vec<AnchorHash>,
}

impl AnchorDag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an anchor. Validates:
    /// - No duplicate IDs (re-inserting the same anchor is OK; returns `Ok(())`)
    /// - All parents already in the DAG
    /// - No cycle introduced
    #[tracing::instrument(skip(self, signed), fields(parents = signed.anchor.parents.len()))]
    pub fn push(&mut self, signed: SignedAnchor) -> std::result::Result<(), DagError> {
        let id = signed.id().map_err(DagError::Internal)?;
        if self.by_id.contains_key(&id) {
            // Idempotent re-insert: same anchor → Ok.
            return Ok(());
        }
        for parent in &signed.anchor.parents {
            if !self.by_id.contains_key(parent) {
                return Err(DagError::ForwardReference {
                    anchor: id,
                    missing_parent: *parent,
                });
            }
        }
        // Cycle check: walk parents transitively, none should be `id`.
        if self.reachable_from_any(&signed.anchor.parents, &id) {
            return Err(DagError::Cycle { anchor: id });
        }
        self.order.push(id);
        self.by_id.insert(id, signed);
        Ok(())
    }

    /// True if `target` is reachable from any of `start_set` by walking
    /// parent edges. Used for cycle detection.
    fn reachable_from_any(&self, start_set: &[AnchorHash], target: &AnchorHash) -> bool {
        let mut visited: HashSet<AnchorHash> = HashSet::new();
        let mut stack: Vec<AnchorHash> = start_set.to_vec();
        while let Some(h) = stack.pop() {
            if &h == target {
                return true;
            }
            if !visited.insert(h) {
                continue;
            }
            if let Some(anchor) = self.by_id.get(&h) {
                stack.extend(anchor.anchor.parents.iter().cloned());
            }
        }
        false
    }

    pub fn get(&self, id: &AnchorHash) -> Option<&SignedAnchor> {
        self.by_id.get(id)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AnchorHash, &SignedAnchor)> {
        self.order.iter().map(move |id| (id, &self.by_id[id]))
    }
    /// Anchor IDs with no children in the DAG. Genesis is not
    /// necessarily a tip — only "no one built on me".
    pub fn tips(&self) -> Vec<AnchorHash> {
        let mut referenced_as_parent: HashSet<AnchorHash> = HashSet::new();
        for anchor in self.by_id.values() {
            for p in &anchor.anchor.parents {
                referenced_as_parent.insert(*p);
            }
        }
        self.order
            .iter()
            .filter(|id| !referenced_as_parent.contains(*id))
            .cloned()
            .collect()
    }

    /// Verify every anchor's signature using a caller-supplied
    /// pubkey resolver. The resolver maps signer fingerprint hex →
    /// PEM pubkey. Anchors whose signer isn't in the resolver are
    /// reported as failed.
    #[tracing::instrument(skip(self, pubkey_resolver), fields(anchors = self.by_id.len()))]
    pub fn verify_signatures<F>(&self, pubkey_resolver: F) -> DagReport
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut reports = Vec::with_capacity(self.order.len());

        for id in &self.order {
            let signed = &self.by_id[id];
            let fp_hex = signed.anchor.signer.fp.to_hex();
            let result = match pubkey_resolver(&fp_hex) {
                Some(pubkey_pem) => signed.verify(&pubkey_pem),
                None => Err(Error::SignatureVerify {
                    key_id: format!("no pubkey registered for signer fingerprint {fp_hex}"),
                }),
            };
            let (ok, error) = match result {
                Ok(()) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };
            reports.push(AnchorReport {
                id: *id,
                parents: signed.anchor.parents.clone(),
                ok,
                error,
            });
        }

        DagReport {
            anchors_total: self.order.len(),
            reports,
            tips: self.tips(),
        }
    }
}

/// DAG construction or validation error.
#[derive(Debug, thiserror::Error)]
pub enum DagError {
    #[error("forward reference in {anchor}: parent {missing_parent} not yet seen")]
    ForwardReference {
        anchor: AnchorHash,
        missing_parent: AnchorHash,
    },

    #[error("cycle detected at {anchor}")]
    Cycle { anchor: AnchorHash },

    #[error("internal error: {0}")]
    Internal(#[source] Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::KeyFp;
    use crate::ledger::anchor::{Anchor, AnchorHash, PayloadHash, SignerId};
    use crate::pki::{self, SigAlgKind};

    fn keypair() -> (String, String, KeyFp) {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        (priv_pem, pub_pem, fp)
    }

    fn genesis_anchor(fp: KeyFp) -> Anchor {
        Anchor::builder(
            SignerId::new(SigAlgKind::Ed25519, fp),
            PayloadHash([1u8; 32]),
        )
        .with_mutations("genesis")
        .build()
    }

    fn child_anchor(parent: AnchorHash, fp: KeyFp, payload_byte: u8) -> Anchor {
        Anchor::builder(
            SignerId::new(SigAlgKind::Ed25519, fp),
            PayloadHash([payload_byte; 32]),
        )
        .with_parent(parent)
        .with_mutations(format!("child {}", payload_byte))
        .build()
    }

    fn signed(anchor: Anchor, priv_pem: &str, pub_pem: &str) -> SignedAnchor {
        anchor.sign(priv_pem, pub_pem, SigAlgKind::Ed25519).unwrap()
    }

    #[test]
    fn empty_dag_has_no_tips() {
        let dag = AnchorDag::new();
        assert!(dag.is_empty());
        assert!(dag.tips().is_empty());
    }

    #[test]
    fn push_genesis_succeeds() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn forward_reference_rejected() {
        let (priv_pem, pub_pem, fp) = keypair();
        let phantom = AnchorHash([0xff; 32]);
        let bad = Anchor::builder(
            SignerId::new(SigAlgKind::Ed25519, fp),
            PayloadHash([2u8; 32]),
        )
        .with_parent(phantom) // not in DAG
        .build();
        let bad_signed = signed(bad, &priv_pem, &pub_pem);

        let mut dag = AnchorDag::new();
        let err = dag.push(bad_signed).unwrap_err();
        assert!(matches!(err, DagError::ForwardReference { .. }));
    }

    #[test]
    fn linear_chain_appends_cleanly() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();

        // Three children off the chain
        let mut prev = g_id;
        for i in 2..=4u8 {
            let a = child_anchor(prev, fp, i);
            let s = signed(a, &priv_pem, &pub_pem);
            let new_id = s.id().unwrap();
            dag.push(s).unwrap();
            prev = new_id;
        }
        assert_eq!(dag.len(), 4);
        assert_eq!(dag.tips().len(), 1); // linear → single tip
    }

    #[test]
    fn fork_produces_two_tips() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();

        let a = signed(child_anchor(g_id, fp, 2), &priv_pem, &pub_pem);
        let b = signed(child_anchor(g_id, fp, 3), &priv_pem, &pub_pem);
        dag.push(a).unwrap();
        dag.push(b).unwrap();

        assert_eq!(dag.len(), 3);
        assert_eq!(dag.tips().len(), 2); // fork
    }

    #[test]
    fn merge_anchor_two_parents() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();

        let a_signed = signed(child_anchor(g_id, fp, 2), &priv_pem, &pub_pem);
        let b_signed = signed(child_anchor(g_id, fp, 3), &priv_pem, &pub_pem);
        let a_id = a_signed.id().unwrap();
        let b_id = b_signed.id().unwrap();
        dag.push(a_signed).unwrap();
        dag.push(b_signed).unwrap();

        // Merge anchor with both as parents
        let merge = Anchor::builder(
            SignerId::new(SigAlgKind::Ed25519, fp),
            PayloadHash([4u8; 32]),
        )
        .with_parent(a_id)
        .with_parent(b_id)
        .with_mutations("merge a + b")
        .build();
        let merge_signed = signed(merge, &priv_pem, &pub_pem);
        dag.push(merge_signed).unwrap();

        assert_eq!(dag.len(), 4);
        assert_eq!(dag.tips().len(), 1); // merge is the only tip
    }

    #[test]
    fn cycle_detected() {
        let (priv_pem, pub_pem, fp) = keypair();

        // Build a small DAG and verify it stays valid as we push more
        // anchors. True cycle detection happens at push-time via
        // reachable_from_any; the only way to attempt a cycle is to
        // forge a parent reference, which `push` rejects as a forward
        // reference first.
        let mut dag = AnchorDag::new();

        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();
        dag.push(g).unwrap();

        let child = signed(child_anchor(g_id, fp, 2), &priv_pem, &pub_pem);
        let child_id = child.id().unwrap();
        dag.push(child).unwrap();

        let grandchild = signed(child_anchor(child_id, fp, 3), &priv_pem, &pub_pem);
        dag.push(grandchild).unwrap();

        // A "self-referential" anchor: tries to claim itself as parent.
        // We can't construct this directly (chicken-and-egg), but we
        // can verify the DAG rejects a forward reference cleanly.
        let phantom = AnchorHash([0xee; 32]);
        let bad = Anchor::builder(
            SignerId::new(SigAlgKind::Ed25519, fp),
            PayloadHash([5u8; 32]),
        )
        .with_parent(phantom)
        .build();
        let bad_signed = signed(bad, &priv_pem, &pub_pem);
        assert!(matches!(
            dag.push(bad_signed),
            Err(DagError::ForwardReference { .. })
        ));

        assert_eq!(dag.len(), 3);
    }

    #[test]
    fn idempotent_reinsert() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g1 = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g2 = g1.clone();

        let mut dag = AnchorDag::new();
        dag.push(g1).unwrap();
        // Re-inserting the same anchor is a no-op (not an error).
        dag.push(g2).unwrap();
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn verify_signatures_all_ok() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();
        dag.push(signed(child_anchor(g_id, fp, 2), &priv_pem, &pub_pem))
            .unwrap();

        let report = dag.verify_signatures(|_fp_hex| Some(pub_pem.clone()));
        assert_eq!(report.anchors_total, 2);
        assert!(report.reports.iter().all(|r| r.ok));
    }

    #[test]
    fn verify_signatures_fails_with_missing_pubkey() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();

        let report = dag.verify_signatures(|_| None);
        assert_eq!(report.anchors_total, 1);
        assert!(!report.reports[0].ok);
        assert!(report.reports[0].error.is_some());
    }

    #[test]
    fn tips_change_after_push() {
        let (priv_pem, pub_pem, fp) = keypair();
        let g = signed(genesis_anchor(fp), &priv_pem, &pub_pem);
        let g_id = g.id().unwrap();

        let mut dag = AnchorDag::new();
        dag.push(g).unwrap();
        assert_eq!(dag.tips(), vec![g_id]);

        let child = signed(child_anchor(g_id, fp, 2), &priv_pem, &pub_pem);
        let child_id = child.id().unwrap();
        dag.push(child).unwrap();
        assert_eq!(dag.tips(), vec![child_id]); // g is no longer a tip
    }
}
