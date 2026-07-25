use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn setup_signed_log() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    let pub_pem = dir.path().join("pub.pem");
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-priv"])
        .arg(&priv_pem)
        .args(["--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("event 1\nevent 2\n")
        .assert()
        .success();

    (dir, log, pub_pem)
}

#[test]
fn snapshot_outputs_chain_head_hash() {
    let (_dir, log, _pub) = setup_signed_log();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .arg("snapshot")
        .arg(&log)
        .assert()
        .success();

    let s = std::str::from_utf8(&out.get_output().stdout)
        .unwrap()
        .trim();
    assert_eq!(s.len(), 64);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn snapshot_without_anchors_outputs_file_hash() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.ept");
    fs::write(&plain, "just text\n").unwrap();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .arg("snapshot")
        .arg(&plain)
        .assert()
        .success();

    let s = std::str::from_utf8(&out.get_output().stdout)
        .unwrap()
        .trim();
    assert_eq!(s.len(), 64);
}

#[test]
fn pin_accepts_correct_hash() {
    let (_dir, log, _pub) = setup_signed_log();
    let head = Command::cargo_bin("enprot")
        .unwrap()
        .arg("snapshot")
        .arg(&log)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let hash = std::str::from_utf8(&head).unwrap().trim().to_string();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("pin")
        .arg(&hash)
        .arg(&log)
        .assert()
        .success();
}

#[test]
fn pin_rejects_wrong_hash() {
    let (_dir, log, _pub) = setup_signed_log();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("pin")
        .arg("0000000000000000000000000000000000000000000000000000000000000000")
        .arg(&log)
        .assert()
        .failure();
}

#[test]
fn pin_detects_tampering() {
    let (_dir, log, _pub) = setup_signed_log();

    let head = Command::cargo_bin("enprot")
        .unwrap()
        .arg("snapshot")
        .arg(&log)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let hash = std::str::from_utf8(&head).unwrap().trim().to_string();

    // Tamper
    let mut content = fs::read_to_string(&log).unwrap();
    content = content.replace("event 1", "TAMPERED");
    fs::write(&log, content).unwrap();

    // Pin should fail because the file's content hash changed.
    // (The chain head hash changes because the anchor's payload changed.)
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("pin")
        .arg(&hash)
        .arg(&log)
        .assert()
        .failure();
}
