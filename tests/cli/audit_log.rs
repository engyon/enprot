use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

// audit-log mode integration (TODO.finalize/27). Stream lines into
// a signed chain, verify later, detect tampering.

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

#[test]
fn audit_log_appends_signed_anchors_per_line() {
    let dir = tempdir().unwrap();
    let (priv_pem, _pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("event 1\nevent 2\nevent 3\n")
        .assert()
        .success();

    let content = fs::read_to_string(&log).unwrap();
    let chain_count = content.matches("// <( CHAIN").count();
    assert_eq!(chain_count, 3, "expected 3 CHAIN blocks (one per line)");

    // Verify linear chain: anchor 1 has no parents, anchor 2 parents
    // off anchor 1, anchor 3 off anchor 2.
    assert!(
        content.contains("parents:"),
        "anchors 2+ must reference parents"
    );
}

#[test]
fn audit_log_verifies_clean() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("login alice\nlogin bob\nlogin carol\n")
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&log)
        .assert()
        .success();
}

#[test]
fn audit_log_detects_tampered_event() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("line one\nline two\nline three\n")
        .assert()
        .success();

    // Tamper: change "line two" to "TAMPERED"
    let mut content = fs::read_to_string(&log).unwrap();
    content = content.replace("line two", "TAMPERED");
    fs::write(&log, content).unwrap();

    // verify-chain must fail (payload hash recomputation catches it).
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&log)
        .assert()
        .failure();
}

#[test]
fn audit_log_detects_deleted_event() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("keep\ndelete me\nkeep\n")
        .assert()
        .success();

    // Tamper: delete the "delete me" line entirely
    let mut content = fs::read_to_string(&log).unwrap();
    content = content.replace("delete me\n", "");
    fs::write(&log, content).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&log)
        .assert()
        .failure();
}

#[test]
fn audit_log_appends_to_existing_file() {
    let dir = tempdir().unwrap();
    let (priv_pem, pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    // First batch
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("batch1\n")
        .assert()
        .success();

    // Second batch — should chain off the first
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("batch2\n")
        .assert()
        .success();

    let content = fs::read_to_string(&log).unwrap();
    let chain_count = content.matches("// <( CHAIN").count();
    assert_eq!(chain_count, 2, "expected 2 CHAIN blocks after two batches");

    // Verify full history
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain", "--trust-root"])
        .arg(&pub_pem)
        .arg(&log)
        .assert()
        .success();
}

#[test]
fn audit_log_empty_stdin_is_a_noop() {
    let dir = tempdir().unwrap();
    let (priv_pem, _pub_pem) = setup_keypair(dir.path());
    let log = dir.path().join("audit.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit-log", "--signer"])
        .arg(&priv_pem)
        .arg(&log)
        .write_stdin("")
        .assert()
        .success();

    assert!(!log.exists(), "file should not be created for empty stdin");
}
