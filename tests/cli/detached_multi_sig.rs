// Integration tests for the detached multi-signature bundle
// (TODO.roadmap/59, local variant of TODO.roadmap/20).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn gen_key(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
    let priv_path = dir.path().join(format!("{name}.priv.pem"));
    let pub_path = dir.path().join(format!("{name}.pub.pem"));
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["keygen", "ed25519"])
        .args(["--out-priv", priv_path.to_str().unwrap()])
        .args(["--out-pub", pub_path.to_str().unwrap()])
        .assert()
        .success();
    priv_path
}

#[test]
fn single_key_sign_produces_raw_bytes_backwards_compat() {
    let dir = tempdir().unwrap();
    let priv1 = gen_key(&dir, "a");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello world").unwrap();

    let sig_path = dir.path().join("msg.txt.sig");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["sign", "--alg", "ed25519"])
        .args(["--key-file", priv1.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();

    let sig_bytes = fs::read(&sig_path).unwrap();
    // Raw Ed25519 signature is 64 bytes.
    assert_eq!(sig_bytes.len(), 64);
    // Bundle header absent.
    let as_str = String::from_utf8_lossy(&sig_bytes);
    assert!(!as_str.contains("enprot-sig/"));
}

#[test]
fn multi_key_sign_produces_bundle_with_all_signers() {
    let dir = tempdir().unwrap();
    let priv1 = gen_key(&dir, "a");
    let priv2 = gen_key(&dir, "b");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello world").unwrap();

    let sig_path = dir.path().join("msg.txt.sig");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["sign", "--alg", "ed25519"])
        .args(["--key-file", priv1.to_str().unwrap()])
        .args(["--key-file", priv2.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();

    let body = fs::read_to_string(&sig_path).unwrap();
    assert!(body.starts_with("enprot-sig/1\n"), "got: {body}");
    // Two entries, one per signer.
    let entry_count = body.matches("alg: ed25519").count();
    assert_eq!(entry_count, 2);
}

#[test]
fn multi_key_verify_accepts_valid_bundle() {
    let dir = tempdir().unwrap();
    let priv1 = gen_key(&dir, "a");
    let pub1 = dir.path().join("a.pub.pem");
    let priv2 = gen_key(&dir, "b");
    let pub2 = dir.path().join("b.pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello world").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["sign", "--alg", "ed25519"])
        .args(["--key-file", priv1.to_str().unwrap()])
        .args(["--key-file", priv2.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify-sig", "--alg", "ed25519"])
        .args(["--key-file", pub1.to_str().unwrap()])
        .args(["--key-file", pub2.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();
}

#[test]
fn multi_key_verify_rejects_missing_signer_pubkey() {
    let dir = tempdir().unwrap();
    let priv1 = gen_key(&dir, "a");
    let priv2 = gen_key(&dir, "b");
    let pub1 = dir.path().join("a.pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello world").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["sign", "--alg", "ed25519"])
        .args(["--key-file", priv1.to_str().unwrap()])
        .args(["--key-file", priv2.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();

    // Wrong pubkey count → reject.
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify-sig", "--alg", "ed25519"])
        .args(["--key-file", pub1.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .failure();
}

#[test]
fn single_key_verify_backwards_compat() {
    // Existing single-sig flow still works.
    let dir = tempdir().unwrap();
    let priv1 = gen_key(&dir, "a");
    let pub1 = dir.path().join("a.pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello world").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["sign", "--alg", "ed25519"])
        .args(["--key-file", priv1.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify-sig", "--alg", "ed25519"])
        .args(["--key-file", pub1.to_str().unwrap()])
        .arg(&msg)
        .assert()
        .success();
}
