use assert_cmd::Command;
use enprot::capability::KeyFp;
use enprot::ledger::{Anchor, AnchorHash, PayloadHash, SignerId, sign_anchor};
use enprot::pki::{self, SigAlgKind};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

// Helper: build a real Ed25519-signed CHAIN block and write it to a
// file alongside the pubkey. Returns the file paths.
fn setup_signed_chain_file() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
    let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
    let fp = KeyFp::from_pem(&pub_pem).unwrap();
    let signer = SignerId::new(SigAlgKind::Ed25519, fp);

    // The payload_hash must match the SHA3-256 of the file content
    // BEFORE this CHAIN block. Since the file is just the CHAIN line
    // itself, the "content before" is empty → SHA3-256 of empty bytes.
    let empty_hash = {
        let policy = enprot::crypto::CryptoPolicyDefault {};
        let hex = enprot::crypto::hexdigest("sha3-256", b"", &policy).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hex::decode(&hex).unwrap());
        PayloadHash(arr)
    };

    let anchor = Anchor::builder(signer, empty_hash)
        .with_mutations("genesis")
        .build();
    let signed = sign_anchor(&anchor, &priv_pem, &pub_pem, SigAlgKind::Ed25519).unwrap();
    let ext = signed.to_extfields();

    let _ = AnchorHash([0u8; 32]); // typecheck AnchorHash is reachable

    // Build a single-line CHAIN directive. BTreeMap iterates sorted,
    // matching what the writer produces.
    let mut line = String::from("// <( CHAIN");
    for (k, v) in &ext {
        line.push_str(&format!(" {}:{}", k, v));
    }
    line.push_str(" )>\n");

    let file_path = dir.path().join("anchor.ept");
    fs::write(&file_path, line).unwrap();

    let pub_path = dir.path().join("pub.pem");
    fs::write(&pub_path, pub_pem).unwrap();

    (dir, file_path, pub_path)
}

#[test]
fn verify_chain_accepts_real_signature() {
    let (_td, file, pub_pem) = setup_signed_chain_file();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(&pub_pem)
        .arg(&file)
        .assert()
        .success();
}

#[test]
fn verify_chain_rejects_when_no_trust_root_supplied() {
    let (_td, file, _pub_pem) = setup_signed_chain_file();
    // No --trust-root: resolver returns None for every fingerprint → fail.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg(&file)
        .assert()
        .failure();
}

#[test]
fn verify_chain_rejects_wrong_trust_root() {
    let (_td, file, _real_pub) = setup_signed_chain_file();

    // Generate an unrelated keypair; verify-chain must reject the
    // anchor because its signer fingerprint isn't in the trust set.
    let other_dir = tempdir().unwrap();
    let other_pub = other_dir.path().join("other.pub");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&other_pub)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(&other_pub)
        .arg(&file)
        .assert()
        .failure();
}

#[test]
fn verify_chain_rejects_synthetic_fixture_with_phantom_parent() {
    // test-data/chain-anchor.ept has a CHAIN block whose parents
    // reference a hash that doesn't appear as an anchor in the file.
    // The DAG constructor must reject this as a forward reference.
    let dir = tempdir().unwrap();
    let pub_pem = dir.path().join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(&pub_pem)
        .arg("test-data/chain-anchor.ept")
        .assert()
        .failure();
}

#[test]
fn verify_chain_handles_empty_file_gracefully() {
    let dir = tempdir().unwrap();
    let empty = dir.path().join("empty.ept");
    fs::write(&empty, "").unwrap();
    let pub_pem = dir.path().join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    // No CHAIN blocks → 0 anchors → all 0 pass. Exit zero.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(&pub_pem)
        .arg(&empty)
        .assert()
        .success();
}

// Re-export to satisfy test-only usage of BTreeMap.
#[allow(dead_code)]
fn _typecheck_btreemap() -> BTreeMap<String, String> {
    BTreeMap::new()
}
