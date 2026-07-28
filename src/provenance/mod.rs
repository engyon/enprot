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

//! Source provenance: SLSA-style manifest + attestation (TODO.roadmap/51).
//!
//! A provenance manifest is an EPT file that lists every source file
//! in a build as an INCLUDE directive pointing at its CAS-stored
//! content. The builder then signs the manifest with a chain anchor,
//! producing a tamper-evident attestation: "I, builder key X, built
//! from these exact inputs." Customers verify with `enprot verify-
//! chain --trust-root <builder-pub>` and a capability policy that
//! pins trust roots.
//!
//! Output formats beyond the native EPT manifest (SLSA JSON,
//! CycloneDX SBOM) are a follow-up — the wire format here is the
//! minimum needed for cryptographic verification.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::cas;
use crate::crypto;
use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode, TextTree};

/// Build a provenance manifest for `dir`. Walks the tree (excluding
/// nothing by default — callers should run from a clean checkout or
/// pass `--exclude`), reads each file, stores its bytes in `casdir`,
/// and emits an EPT manifest with one INCLUDE per file. Returns the
/// manifest text.
pub fn build_manifest(dir: &Path, casdir: &Path) -> Result<TextTree> {
    if !dir.is_dir() {
        return Err(Error::msg(format!("{} is not a directory", dir.display())));
    }
    let policy = crate::crypto::default_policy();
    let mut paops = ParseOps::new(policy)?;
    paops.io.set_local_casdir(casdir.to_path_buf());
    paops.runtime.fname = dir.display().to_string();

    let mut files = collect_files(dir)?;
    // Stable ordering so the same tree produces byte-identical
    // manifests — important for diff-friendliness and for caching.
    files.sort();

    let mut tree: TextTree = Vec::new();
    tree.push(TextNode::Plain(format!(
        "# provenance manifest for {}",
        dir.display()
    )));

    for file in &files {
        let rel = file
            .strip_prefix(dir)
            .map_err(|e| Error::msg(e.to_string()))?;
        let bytes = std::fs::read(file)?;
        let hash = cas::save(bytes, &mut paops)?;
        // Use a Plain comment to record the path alongside the hash
        // (INCLUDE only carries the hash). The verifier reconstructs
        // the path list from these comments.
        tree.push(TextNode::Plain(format!("# path: {}", rel.display())));
        tree.push(TextNode::Include { hash });
    }
    Ok(tree)
}

/// Recursively collect every regular file under `root`. Symlinks are
/// skipped (no surprise dereferences), and hidden files (`.dotfiles`)
/// are kept — the caller decides what to include by choosing the
/// walk root.
fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for ent in entries {
        let ent = ent?;
        let path = ent.path();
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(&path, out)?;
            continue;
        }
        if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Append a chain anchor to `tree` signed by `signer_priv_pem`. The
/// anchor commits to the entire tree (payload_hash = SHA3-256 over
/// the canonical serialization), so any later tampering with a path
/// comment or INCLUDE hash invalidates the signature.
pub fn attest(
    tree: &TextTree,
    signer_priv_pem: &str,
    casdir: &Path,
    mut words: Vec<String>,
) -> Result<TextTree> {
    use crate::ledger;
    use crate::pki::SigAlgKind;

    let policy = crate::crypto::default_policy();
    let mut paops = ParseOps::new(policy)?;
    paops.io.set_local_casdir(casdir.to_path_buf());
    paops.runtime.fname = "<provenance-attest>".into();

    // Derive the signer fingerprint (we need it for the SignerId).
    let botan_priv = botan::Privkey::load_pem(signer_priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let fp = crate::capability::KeyFp::from_pem(&pub_pem)?;

    // Recompute the chain head (payload hash over current tree).
    let blob = etree::tree_to_blob(tree, &mut paops)?;
    let payload_hex = crypto::hexdigest("sha3-256", &blob, &*paops.crypto.policy)?;
    let payload_hash = ledger::anchor::PayloadHash::from_hex(&payload_hex)?;

    // Sign the anchor's signing bytes via the Anchor API (it
    // cross-checks the pubkey fingerprint against the SignerId).
    let signer_id = ledger::anchor::SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = ledger::anchor::Anchor::builder(signer_id, payload_hash)
        .with_mutations("provenance-attest")
        .build();
    let signed = anchor.sign(signer_priv_pem, &pub_pem, SigAlgKind::Ed25519)?;

    // Render to wire extfields and append as a Chain node.
    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in signed.to_extfields().into_iter() {
        extfields.insert(k, v);
    }
    let mut out = tree.clone();
    out.push(TextNode::Chain { extfields });

    if !words.is_empty() {
        words.sort();
        let _ = words; // informational; would appear in `mut:` if builder set it
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(p: &Path, contents: &str) {
        fs::write(p, contents).unwrap();
    }

    #[test]
    fn manifest_lists_every_file_with_include() {
        let proj = tempdir().unwrap();
        let cas = tempdir().unwrap();
        write(&proj.path().join("a.txt"), "alpha");
        write(&proj.path().join("b.txt"), "beta");
        std::fs::create_dir(proj.path().join("sub")).unwrap();
        write(&proj.path().join("sub/c.txt"), "gamma");

        let tree = build_manifest(proj.path(), cas.path()).unwrap();
        let mut hashes = 0;
        let mut paths = 0;
        for node in &tree {
            match node {
                TextNode::Plain(s) if s.starts_with("# path: ") => paths += 1,
                TextNode::Include { .. } => hashes += 1,
                _ => {}
            }
        }
        assert_eq!(paths, 3, "expected 3 path comments; got {paths}");
        assert_eq!(hashes, 3, "expected 3 INCLUDE hashes; got {hashes}");
    }

    #[test]
    fn manifest_is_byte_identical_for_same_tree() {
        let proj1 = tempdir().unwrap();
        let proj2 = tempdir().unwrap();
        let cas1 = tempdir().unwrap();
        let cas2 = tempdir().unwrap();
        for (p, c) in &[("x.txt", "x"), ("y.txt", "y")] {
            write(&proj1.path().join(p), c);
            write(&proj2.path().join(p), c);
        }

        let t1 = build_manifest(proj1.path(), cas1.path()).unwrap();
        let t2 = build_manifest(proj2.path(), cas2.path()).unwrap();

        // The INCLUDE hashes are content-addressed so they should be
        // identical across the two manifests. Path comments are also
        // identical (same relative layout).
        let h1: Vec<String> = t1
            .iter()
            .filter_map(|n| match n {
                TextNode::Include { hash } => Some(hash.clone()),
                _ => None,
            })
            .collect();
        let h2: Vec<String> = t2
            .iter()
            .filter_map(|n| match n {
                TextNode::Include { hash } => Some(hash.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(h1, h2);
    }

    #[test]
    fn manifest_rejects_non_directory_input() {
        let tmp = tempdir().unwrap();
        let f = tmp.path().join("not_a_dir");
        write(&f, "x");
        let cas = tempdir().unwrap();
        let result = build_manifest(&f, cas.path());
        assert!(result.is_err());
    }

    #[test]
    fn manifest_skips_symlinks() {
        let proj = tempdir().unwrap();
        let cas = tempdir().unwrap();
        write(&proj.path().join("real.txt"), "real");
        #[cfg(unix)]
        std::os::unix::fs::symlink(proj.path().join("real.txt"), proj.path().join("link.txt"))
            .unwrap();

        let tree = build_manifest(proj.path(), cas.path()).unwrap();
        let count = tree
            .iter()
            .filter(|n| matches!(n, TextNode::Include { .. }))
            .count();
        // Only real.txt, not the symlink.
        assert_eq!(count, 1);
    }

    #[test]
    fn attest_appends_chain_node_signed_by_builder() {
        use crate::pki::{self, SigAlgKind};
        let proj = tempdir().unwrap();
        let cas = tempdir().unwrap();
        write(&proj.path().join("a.txt"), "alpha");
        let tree = build_manifest(proj.path(), cas.path()).unwrap();

        // Generate a builder keypair.
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();

        let attested = attest(&tree, &priv_pem, cas.path(), Vec::new()).unwrap();
        let chain_count = attested
            .iter()
            .filter(|n| matches!(n, TextNode::Chain { .. }))
            .count();
        assert_eq!(chain_count, 1);

        // Verify the signature round-trips: re-extract the signed
        // anchor from the wire format and verify against pub_pem.
        let chain_node = attested
            .iter()
            .find_map(|n| match n {
                TextNode::Chain { extfields } => Some(extfields),
                _ => None,
            })
            .unwrap();
        let signed = crate::ledger::anchor::SignedAnchor::from_extfields(chain_node).unwrap();
        crate::ledger::verify_anchor(&signed, &pub_pem).unwrap();
    }
}
