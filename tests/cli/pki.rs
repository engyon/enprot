use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

// PQC Phase 1: Ed25519 keygen / sign / verify-sig end-to-end through
// the CLI. The unit tests in src/pki.rs cover the library surface;
// these tests prove the wiring through `app_main` is correct
// (subcommand dispatch, file I/O, default `.sig` extension, stdin/stdout).

#[test]
fn keygen_writes_pem_pair() {
    let dir = tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    let pub_pem = dir.path().join("pub.pem");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("keygen")
        .arg("ed25519")
        .arg("--out-priv")
        .arg(&priv_pem)
        .arg("--out-pub")
        .arg(&pub_pem)
        .assert()
        .success();

    let priv_text = fs::read_to_string(&priv_pem).unwrap();
    let pub_text = fs::read_to_string(&pub_pem).unwrap();
    assert!(priv_text.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(priv_text.contains("-----END PRIVATE KEY-----"));
    assert!(pub_text.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(pub_text.contains("-----END PUBLIC KEY-----"));
}

#[test]
fn sign_default_sig_extension_round_trips() {
    let dir = tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    let pub_pem = dir.path().join("pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"hello enprot").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("keygen")
        .arg("ed25519")
        .arg("--out-priv")
        .arg(&priv_pem)
        .arg("--out-pub")
        .arg(&pub_pem)
        .assert()
        .success();

    // `enprot sign --alg ed25519 --key priv.pem msg.txt` produces msg.txt.sig
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("sign")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&priv_pem)
        .arg(&msg)
        .assert()
        .success();

    let sig_path = dir.path().join("msg.txt.sig");
    assert!(sig_path.exists(), "default .sig extension not applied");
    let sig = fs::read(&sig_path).unwrap();
    assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");

    // `enprot verify-sig --alg ed25519 --key pub.pem msg.txt` reads msg.txt.sig
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-sig")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&pub_pem)
        .arg(&msg)
        .assert()
        .success();
}

#[test]
fn verify_sig_fails_on_tampered_message() {
    let dir = tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    let pub_pem = dir.path().join("pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"original").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("keygen")
        .arg("ed25519")
        .arg("--out-priv")
        .arg(&priv_pem)
        .arg("--out-pub")
        .arg(&pub_pem)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("sign")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&priv_pem)
        .arg(&msg)
        .assert()
        .success();

    // Mutate the message after signing.
    fs::write(&msg, b"TAMPERED").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-sig")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&pub_pem)
        .arg(&msg)
        .assert()
        .failure();
}

#[test]
fn verify_sig_fails_with_wrong_key() {
    let dir = tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    let other_pub_pem = dir.path().join("other.pub.pem");
    let msg = dir.path().join("msg.txt");
    fs::write(&msg, b"signed by priv, verified by other").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("keygen")
        .arg("ed25519")
        .arg("--out-priv")
        .arg(&priv_pem)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("keygen")
        .arg("ed25519")
        .arg("--out-pub")
        .arg(&other_pub_pem)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("sign")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&priv_pem)
        .arg(&msg)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-sig")
        .arg("--alg")
        .arg("ed25519")
        .arg("--key-file")
        .arg(&other_pub_pem)
        .arg(&msg)
        .assert()
        .failure();
}
