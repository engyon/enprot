use assert_cmd::Command;
use enprot::capability::KeyFp;
use enprot::ledger::{Anchor, AnchorHash, PayloadHash, SignerId, sign_anchor};
use enprot::pki::{self, SigAlgKind};
use std::fs;
use tempfile::tempdir;

// `--anchor` flag integration: producing chain anchors during
// encrypt/store and verifying them via verify-chain. End-to-end
// test of TODO.finalize/17's "produce anchors" side.

fn setup_keypair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let priv_pem = dir.join("priv.pem");
    let pub_pem = dir.join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-priv"])
        .arg(&priv_pem)
        .args(["--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();
    (priv_pem, pub_pem)
}

fn write_secret_file(path: &std::path::Path) {
    let body = "// <( BEGIN Secret )>\nplaintext\n// <( END Secret )>\n";
    fs::write(path, body).unwrap();
}

#[test]
fn encrypt_anchor_produces_chain_block() {
    let dir = tempdir().unwrap();
    let (priv_pem, _pub_pem) = setup_keypair(dir.path());
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("file.ept");
    write_secret_file(&ept);

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(&cas)
        .args(["encrypt", "-w", "Secret", "-k", "Secret=password"])
        .args(["--pbkdf", "legacy"])
        .args(["--anchor", "--signer"])
        .arg(&priv_pem)
        .arg(&ept)
        .assert()
        .success();

    let after = fs::read_to_string(&ept).unwrap();
    assert!(
        after.contains("// <( CHAIN"),
        "expected CHAIN block in output, got:\n{}",
        after
    );
    assert!(after.contains("signer:ed25519:"));
    assert!(after.contains("payload:"));
    assert!(after.contains("sig:"));
    assert!(
        after.contains("mut:encrypt+Secret"),
        "expected mut:encrypt+Secret, got: {}",
        after
    );
}

#[test]
fn anchor_then_verify_chain_round_trips() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("file.ept");
    write_secret_file(&ept);

    // Encrypt + anchor
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(&cas)
        .args(["encrypt", "-w", "Secret", "-k", "Secret=password"])
        .args(["--pbkdf", "legacy"])
        .args(["--anchor", "--signer"])
        .arg(&priv_pem)
        .arg(&ept)
        .assert()
        .success();

    // Verify
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&ept)
        .assert()
        .success();
}

#[test]
fn anchor_requires_signer() {
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("file.ept");
    write_secret_file(&ept);

    // --anchor without --signer must fail cleanly.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(&cas)
        .args(["encrypt", "-w", "Secret", "-k", "Secret=password"])
        .args(["--pbkdf", "legacy", "--anchor"])
        .arg(&ept)
        .assert()
        .failure();
}

#[test]
fn anchor_rejects_wrong_pubkey_in_verify() {
    let dir = tempdir().unwrap();
    let (priv_pem, _real_pub) = setup_keypair(dir.path());
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("file.ept");
    write_secret_file(&ept);

    // Encrypt with priv
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(&cas)
        .args(["encrypt", "-w", "Secret", "-k", "Secret=password"])
        .args(["--pbkdf", "legacy"])
        .args(["--anchor", "--signer"])
        .arg(&priv_pem)
        .arg(&ept)
        .assert()
        .success();

    // Verify with an unrelated pubkey
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
        .args(["verify-chain", "--trust-root"])
        .arg(&other_pub)
        .arg(&ept)
        .assert()
        .failure();
}

#[test]
fn anchor_tampered_payload_fails_verify() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("file.ept");
    write_secret_file(&ept);

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(&cas)
        .args(["encrypt", "-w", "Secret", "-k", "Secret=password"])
        .args(["--pbkdf", "legacy"])
        .args(["--anchor", "--signer"])
        .arg(&priv_pem)
        .arg(&ept)
        .assert()
        .success();

    // Tamper: flip the first payload hex char
    let mut content = fs::read_to_string(&ept).unwrap();
    let old = "payload:";
    let idx = content.find(old).unwrap() + old.len();
    let original = content.as_bytes()[idx];
    let tampered = if original == b'0' { b'1' } else { b'0' };
    let mut bytes = content.into_bytes();
    bytes[idx] = tampered;
    content = String::from_utf8(bytes).unwrap();
    fs::write(&ept, content).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&ept)
        .assert()
        .failure();
}

// Reference helpers used by some assertions to verify library types
// align with the wire format. Suppresses dead-code warnings.
#[allow(dead_code)]
fn _wire_format_check() {
    let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
    let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
    let fp = KeyFp::from_pem(&pub_pem).unwrap();
    let signer = SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = Anchor::builder(signer, PayloadHash([0u8; 32])).build();
    let _signed = sign_anchor(&anchor, &priv_pem, &pub_pem, SigAlgKind::Ed25519).unwrap();
    let _h = AnchorHash([0u8; 32]);
}
