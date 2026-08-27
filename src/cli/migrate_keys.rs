// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the above disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY EXPRESS OR INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! `enprot migrate-keys` — re-sign CHAIN anchors under a new key and
//! algorithm (TODO.complete/58, the post-quantum migration path).
//!
//! Migration is **per-anchor**: each `CHAIN` block carries
//! `signer:<alg>:<fp>` and is self-describing, so a file may hold
//! classical and post-quantum anchors side by side (the hybrid
//! period) and `verify-chain` checks each against its own algorithm.
//!
//! Two invariants drive the implementation:
//!
//! 1. **Fail closed.** Every anchor matching `--from` + `--old-key`
//!    is verified against the old public key *before* anything is
//!    rewritten. One tampered anchor aborts the whole file, leaving
//!    it untouched.
//! 2. **The chain stays closed.** An anchor's ID hashes its signing
//!    bytes, which include the signer — so re-signing changes the
//!    ID, and children reference parents by ID. Migrated anchors get
//!    their parents rewired to the new IDs (migrated in document
//!    order, which is topological: the DAG forbids forward
//!    references). An anchor that references a migrated parent but
//!    is itself signed by a different key cannot be migrated here —
//!    rewriting its parents would invalidate its own signature — so
//!    the command refuses rather than silently breaking it.
//! 3. **Payloads stay truthful.** An anchor's `payload:` commits to
//!    the exact bytes of everything before it — including earlier
//!    anchors. Re-signing an ancestor changes those bytes, so a
//!    migrated anchor's payload is recomputed over the rewritten
//!    prefix (identical to the original when nothing before it
//!    migrated). The whole file's payloads are verified up front, so
//!    re-signing can never launder tampered content into a fresh
//!    commitment.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::BufReader;

use crate::capability::KeyFp;
use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode, TextTree};
use crate::ledger::{AnchorHash, SignedAnchor, SignerId};
use crate::pki::{self, SigAlgKind};

use super::{CommonArgs, MigrateKeysSubcmd, apply_common, resolve_policy};

/// Fully-resolved migration parameters: the keys, algorithms, and
/// the new signer identity every migrated anchor will carry.
struct Migration {
    from: SigAlgKind,
    to: SigAlgKind,
    old_fp: KeyFp,
    old_pub_pem: String,
    new_priv_pem: String,
    new_pub_pem: String,
    new_signer: SignerId,
}

pub(super) fn run(common: CommonArgs, a: MigrateKeysSubcmd) -> Result<()> {
    if a.files.is_empty() {
        return Err(Error::InvalidArg {
            arg: "FILE",
            reason: "migrate-keys needs at least one FILE".to_string(),
        });
    }
    if let Some(f) = a.files.iter().find(|f| f.as_str() == "-") {
        return Err(Error::InvalidArg {
            arg: "FILE",
            reason: format!(
                "stdin ('{f}') not supported: the rewrite must be written back in place"
            ),
        });
    }

    let from: SigAlgKind = a.from.parse()?;
    let to: SigAlgKind = a.to.parse()?;
    if from == to {
        return Err(Error::InvalidArg {
            arg: "--to",
            reason: format!("--from and --to are both {}", from.name()),
        });
    }

    let old_pub_pem = fs::read_to_string(&a.old_key)?;
    let new_priv_pem = fs::read_to_string(&a.new_key)?;
    let migration = build_migration(from, to, &old_pub_pem, &new_priv_pem)?;

    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    for path in &a.files {
        migrate_one_file(path, &migration, &mut paops)?;
    }
    Ok(())
}

/// Resolve and cross-check the key material. Fails fast (before any
/// file is touched) on a key that doesn't match `--to`.
fn build_migration(
    from: SigAlgKind,
    to: SigAlgKind,
    old_pub_pem: &str,
    new_priv_pem: &str,
) -> Result<Migration> {
    let new_pub_pem = pki::pubkey_from_priv_pem(to, new_priv_pem)?;
    let new_fp = KeyFp::from_pem(&new_pub_pem)?;

    // The priv PEM must actually be usable under `--to` — an
    // ed25519 key passed with `--to mldsa` would otherwise only
    // surface as a verification failure on every anchor.
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
    let probe = pki::sign(to, new_priv_pem, b"enprot-migrate-keys-probe", &mut rng)?;
    if !pki::verify(to, &new_pub_pem, b"enprot-migrate-keys-probe", &probe)? {
        return Err(Error::InvalidArg {
            arg: "--new-key",
            reason: "probe signature under --to failed; key does not match --to".to_string(),
        });
    }

    Ok(Migration {
        from,
        to,
        old_fp: KeyFp::from_pem(old_pub_pem)?,
        old_pub_pem: old_pub_pem.to_string(),
        new_priv_pem: new_priv_pem.to_string(),
        new_signer: SignerId::new(to, new_fp),
        new_pub_pem,
    })
}

/// One file: parse → plan (verify everything) → rewrite → write back
/// in place. On any error the file is left exactly as it was.
fn migrate_one_file(path: &str, m: &Migration, paops: &mut ParseOps) -> Result<()> {
    paops.runtime.fname = path.into();
    let reader = File::open(path)
        .map_err(|e| Error::Io(std::io::Error::other(format!("Failed to open {path}: {e}"))))?;
    let mut tree = etree::parse(BufReader::new(reader), paops)?;

    let plan = plan_tree(&tree, m, paops)?;
    if plan.migrate.is_empty() {
        println!(
            "{path}: no anchors signed by {} under the --old-key fingerprint; nothing to do",
            m.from.name()
        );
        return Ok(());
    }

    let mut id_map = HashMap::new();
    let migrated = rewrite_tree(&mut tree, m, &plan.migrate, &mut id_map, paops)?;
    debug_assert_eq!(migrated, plan.migrate.len());
    debug_assert_eq!(id_map.len(), plan.migrate.len());

    // Write back in place. The tree was fully transformed in memory;
    // a write failure leaves a partial file, matching the in-place
    // convention of the transform pipeline.
    let mut out = File::create(path)?;
    etree::tree_write(&mut out, &tree, paops)?;

    println!(
        "{path}: migrated {migrated} anchor(s) {} -> {}",
        m.from.name(),
        m.to.name(),
    );
    Ok(())
}

/// Pass 1: classify every CHAIN anchor and verify the migratable
/// ones. Collects the old anchor IDs to migrate; returns an error on
/// anything that makes the file unsafe to rewrite.
struct Plan {
    migrate: HashSet<AnchorHash>,
}

fn plan_tree(tree: &TextTree, m: &Migration, paops: &mut ParseOps) -> Result<Plan> {
    // Fail closed on tampered content BEFORE any rewrite: every
    // recorded payload must match the file as it stands, so the
    // payload recomputation below can never re-commit tampered
    // bytes under the new key. Mirrors verify-chain's check.
    let mut prefix: TextTree = Vec::new();
    let policy = crate::crypto::CryptoPolicyDefault {};
    for node in tree.iter() {
        if let TextNode::Chain { extfields } = node {
            let blob = etree::tree_to_blob(&prefix, paops)?;
            let recomputed = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
            let recorded = extfields.get("payload").map(|s| s.as_str()).unwrap_or("");
            if recomputed != recorded {
                return Err(Error::CasHashMismatch {
                    expected: recorded.to_string(),
                    actual: recomputed,
                });
            }
        }
        prefix.push(node.clone());
    }

    let mut anchors = Vec::new();
    collect(tree, &mut anchors)?;
    let mut migrate = HashSet::new();
    for signed in &anchors {
        if signed.anchor.signer.fp == m.old_fp {
            if !signed.co_signatures.is_empty() {
                return Err(Error::InvalidArg {
                    arg: "--from",
                    reason: format!(
                        "multi-sig anchor {} carries co-signatures; \
                         multi-signer migration is not supported yet",
                        signed.anchor.signer
                    ),
                });
            }
            if signed.anchor.signer.alg != m.from {
                return Err(Error::InvalidArg {
                    arg: "--from",
                    reason: format!(
                        "anchor signed by the --old-key under {}, but --from is {}; \
                         pass the algorithm the anchors actually use",
                        signed.anchor.signer.alg.name(),
                        m.from.name()
                    ),
                });
            }
            // Fail closed: a tampered anchor must never be silently
            // re-signed under the new key.
            signed.verify(&m.old_pub_pem)?;
            migrate.insert(signed.id()?);
        }
    }
    // Descendants by other signers would dangle: their parents field
    // embeds the old hash, and updating it breaks their signature.
    for signed in &anchors {
        let id = signed.id()?;
        if migrate.contains(&id) {
            continue;
        }
        if signed.anchor.parents.iter().any(|p| migrate.contains(p)) {
            return Err(Error::InvalidArg {
                arg: "FILE",
                reason: format!(
                    "anchor {} ({}) references a migrated parent but is signed by a \
                     different key; its signature would be invalidated",
                    id, signed.anchor.signer
                ),
            });
        }
    }
    Ok(Plan { migrate })
}

fn collect(tree: &TextTree, out: &mut Vec<SignedAnchor>) -> Result<()> {
    // Collect in one pass, THEN propagate errors — the visitor
    // callback can't return Result, so failures surface after the
    // walk (identical semantics: any bad anchor fails the plan).
    let mut bad: Option<crate::error::Error> = None;
    etree::visitor::visit(tree, &mut |node| {
        if let TextNode::Chain { extfields } = node {
            match SignedAnchor::from_extfields(extfields) {
                Ok(signed) => out.push(signed),
                Err(e) => {
                    if bad.is_none() {
                        bad = Some(e);
                    }
                }
            }
        }
        etree::visitor::Control::Continue
    });
    match bad {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Pass 2: rewrite the migratable anchors in document order
/// (topological — the DAG forbids forward parent references), so a
/// parent's new ID is always in `id_map` by the time a child needs
/// it. Parent hashes that were not migrated (other signers, or
/// references into other files) are carried over unchanged.
fn rewrite_tree(
    tree: &mut TextTree,
    m: &Migration,
    migrate: &HashSet<AnchorHash>,
    id_map: &mut HashMap<AnchorHash, AnchorHash>,
    paops: &mut ParseOps,
) -> Result<usize> {
    let mut count = 0;
    let policy = crate::crypto::CryptoPolicyDefault {};
    for i in 0..tree.len() {
        // Index-based loop: `tree[..i]` is the already-rewritten
        // prefix, which is exactly what the payload commits to. The
        // identification and payload computation happen under an
        // immutable borrow, before the node is taken mutably.
        let migrate_this = match &tree[i] {
            TextNode::Chain { extfields } => {
                migrate.contains(&SignedAnchor::from_extfields(extfields)?.id()?)
            }
            _ => false,
        };
        // Top-level anchors: payload = SHA3-256 over the rewritten
        // prefix (verify-chain's formula). For the first migrated
        // anchor this equals the original payload; for descendants
        // it re-commits the legitimately changed bytes.
        let payload_hash = if migrate_this {
            let blob = etree::tree_to_blob(tree[..i].to_vec().as_ref(), paops)?;
            let payload_hex = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
            let mut payload_arr = [0u8; 32];
            payload_arr.copy_from_slice(&hex::decode(payload_hex)?);
            Some(crate::ledger::PayloadHash(payload_arr))
        } else {
            None
        };
        match &mut tree[i] {
            TextNode::Chain { extfields } => {
                let signed = SignedAnchor::from_extfields(extfields)?;
                let old_id = signed.id()?;
                if !migrate.contains(&old_id) {
                    continue;
                }
                let payload_hash = payload_hash.expect("computed above for migratable anchors");
                let parents = signed
                    .anchor
                    .parents
                    .iter()
                    .map(|p| id_map.get(p).copied().unwrap_or(*p))
                    .collect();
                let mut builder =
                    crate::ledger::Anchor::builder(m.new_signer.clone(), payload_hash)
                        .with_parents(parents)
                        .with_mutations(signed.anchor.mutations.clone());
                if let Some(ref ts) = signed.anchor.timestamp {
                    builder = builder.with_timestamp(ts.clone());
                }
                let new_signed = builder
                    .build()
                    .sign(&m.new_priv_pem, &m.new_pub_pem, m.to)?;
                *extfields = new_signed.to_extfields();
                id_map.insert(old_id, new_signed.id()?);
                count += 1;
            }
            TextNode::BeginEnd { txt, .. } | TextNode::Encrypted { txt, .. } => {
                count += rewrite_nested(txt, m, migrate, id_map)?;
            }
            _ => {}
        }
    }
    Ok(count)
}

/// Nested CHAIN anchors (inside BEGIN/END or ENCRYPTED blocks):
/// re-sign with the original payload preserved. verify-chain's
/// payload check only covers top-level anchors, so there is no
/// prefix formula to recompute against.
fn rewrite_nested(
    tree: &mut TextTree,
    m: &Migration,
    migrate: &HashSet<AnchorHash>,
    id_map: &mut HashMap<AnchorHash, AnchorHash>,
) -> Result<usize> {
    let mut count = 0;
    for node in tree.iter_mut() {
        match node {
            TextNode::Chain { extfields } => {
                let signed = SignedAnchor::from_extfields(extfields)?;
                let old_id = signed.id()?;
                if !migrate.contains(&old_id) {
                    continue;
                }
                let parents = signed
                    .anchor
                    .parents
                    .iter()
                    .map(|p| id_map.get(p).copied().unwrap_or(*p))
                    .collect();
                let mut builder = crate::ledger::Anchor::builder(
                    m.new_signer.clone(),
                    signed.anchor.payload_hash,
                )
                .with_parents(parents)
                .with_mutations(signed.anchor.mutations.clone());
                if let Some(ref ts) = signed.anchor.timestamp {
                    builder = builder.with_timestamp(ts.clone());
                }
                let new_signed = builder
                    .build()
                    .sign(&m.new_priv_pem, &m.new_pub_pem, m.to)?;
                *extfields = new_signed.to_extfields();
                id_map.insert(old_id, new_signed.id()?);
                count += 1;
            }
            TextNode::BeginEnd { txt, .. } | TextNode::Encrypted { txt, .. } => {
                count += rewrite_nested(txt, m, migrate, id_map)?;
            }
            _ => {}
        }
    }
    Ok(count)
}
