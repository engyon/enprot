//! `enprot snapshot` / `pin` / `audit-log` — chain-head commands.
//!
//! These three commands operate on the chain head (the AnchorHash of
//! the last CHAIN block, or a full-file SHA3-256 if the file has no
//! anchors). They share `compute_chain_head` and the chain-anchor
//! builder `build_chain_anchor_node_with_parent` (audit-log path).

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::ledger;

use super::{AuditLogSubcmd, CommonArgs, PinSubcmd, SnapshotSubcmd, walk_for_chains};

/// Compute the chain head hash of a file: SHA3-256 over the
/// canonical serialized tree. This detects ANY byte-level change —
/// content, anchors, metadata. For external pinning (publish the
/// hash out-of-band, later compare with `enprot pin`), this is the
/// strongest guarantee.
fn compute_chain_head(path: &str) -> Result<String> {
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    paops.runtime.fname = path.to_string();
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(std::fs::File::open(path)?))
    };
    let tree = etree::parse(reader, &mut paops)?;

    // Always hash the full canonical tree serialization. This catches
    // any tampering — content, anchors, separators, whitespace.
    let mut blob = Vec::new();
    etree::tree_write(&mut blob, &tree, &mut paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    crate::crypto::hexdigest("sha3-256", &blob, &policy)
}

pub fn snapshot(a: SnapshotSubcmd) -> Result<()> {
    let head = compute_chain_head(&a.file)?;
    println!("{}", head);
    Ok(())
}

pub fn pin(a: PinSubcmd) -> Result<()> {
    let head = compute_chain_head(&a.file)?;
    if head == a.expected {
        println!("OK");
        Ok(())
    } else {
        Err(Error::SignatureVerify {
            key_id: format!("chain head mismatch: expected {}, got {}", a.expected, head),
        })
    }
}

/// `audit-log` implementation: read stdin lines, append each as a
/// signed CHAIN anchor to FILE. The result is a linear, tamper-evident
/// log where each anchor's parent is the previous anchor (or empty
/// for the genesis line).
pub fn audit_log_stream(_common: CommonArgs, a: AuditLogSubcmd) -> Result<()> {
    let priv_pem = fs::read_to_string(&a.signer)?;

    // Read existing content (if any) → tree. Missing file = empty tree.
    let mut tree: etree::TextTree = if Path::new(&a.file).exists() {
        let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
        paops.runtime.fname = a.file.clone();
        let f = std::fs::File::open(&a.file)?;
        etree::parse(BufReader::new(f), &mut paops)?
    } else {
        Vec::new()
    };

    // Find the most recent existing CHAIN anchor; new lines chain off it.
    let mut last_anchor = latest_anchor_hash(&tree);

    // Read stdin lines.
    let stdin = std::io::stdin();
    let mut line_count = 0usize;
    for line_in in stdin.lock().lines() {
        let line = line_in?;
        // Strip a trailing newline if present (lines() already does;
        // be defensive in case callers pipe raw bytes).
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        tree.push(etree::TextNode::Plain(trimmed.to_string()));

        let chain_node =
            build_chain_anchor_node_with_parent(&tree, &priv_pem, "append", "", last_anchor)?;
        // Track the new anchor's hash so the next iteration parents off it.
        if let etree::TextNode::Chain { extfields } = &chain_node
            && let Ok(signed) = ledger::SignedAnchor::from_extfields(extfields)
            && let Ok(h) = signed.id()
        {
            last_anchor = Some(h);
        }
        tree.push(chain_node);
        line_count += 1;
    }

    if line_count == 0 {
        eprintln!("audit-log: no lines read from stdin; file unchanged.");
        return Ok(());
    }

    // Write the full tree back atomically.
    let tmp_path = format!("{}.tmp", a.file);
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    paops.runtime.fname = a.file.clone();
    let mut writer = BufWriter::new(std::fs::File::create(&tmp_path)?);
    etree::tree_write(&mut writer, &tree, &mut paops)?;
    writer.flush()?;
    drop(writer);
    fs::rename(&tmp_path, &a.file)?;

    eprintln!("audit-log: appended {} anchor(s) to {}", line_count, a.file);
    Ok(())
}

/// Walk the tree and return the [`AnchorHash`](crate::ledger::AnchorHash)
/// of the LAST [`TextNode::Chain`] in document order, or `None` if
/// the tree has no anchors. Used by [`audit_log_stream`] to extend
/// the linear chain.
fn latest_anchor_hash(tree: &etree::TextTree) -> Option<ledger::AnchorHash> {
    let mut all = Vec::new();
    let _ = walk_for_chains(tree, &mut all);
    all.pop()
}

/// Build a [`TextNode::Chain`] signing the post-content state of
/// `tree`, with explicit `parent` (None for genesis). Used by
/// [`audit_log_stream`] where the parent is the previous anchor in
/// the stream, not all anchors in the file.
fn build_chain_anchor_node_with_parent(
    tree: &etree::TextTree,
    priv_pem: &str,
    operation: &str,
    words_csv: &str,
    parent: Option<ledger::AnchorHash>,
) -> Result<etree::TextNode> {
    use crate::ledger::{Anchor, PayloadHash, SignerId};
    use crate::pki::SigAlgKind;
    use std::collections::BTreeMap;

    // Derive pubkey from privkey.
    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let fp = crate::capability::KeyFp::from_pem(&pub_pem)?;

    // payload_hash: SHA3-256 over EVERYTHING currently in the tree
    // (including any prior CHAIN blocks). This gives end-to-end tamper
    // detection: changing any earlier content invalidates every
    // subsequent anchor's payload. The anchor itself isn't in `tree`
    // yet (the caller pushes it AFTER this function returns), so no
    // self-reference.
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    let blob = etree::tree_to_blob(tree, &mut paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    let payload_hex = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
    let mut payload_arr = [0u8; 32];
    payload_arr.copy_from_slice(&hex::decode(payload_hex)?);
    let payload_hash = PayloadHash(payload_arr);

    let mutations = if words_csv.is_empty() {
        operation.to_string()
    } else {
        format!("{}+{}", operation, words_csv)
    };

    let parents: Vec<_> = parent.into_iter().collect();
    let signer = SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = Anchor::builder(signer, payload_hash)
        .with_parents(parents)
        .with_mutations(mutations)
        .build();
    let signed = anchor.sign(priv_pem, &pub_pem, SigAlgKind::Ed25519)?;
    let extfields: BTreeMap<String, String> = signed.to_extfields();
    Ok(etree::TextNode::Chain { extfields })
}
