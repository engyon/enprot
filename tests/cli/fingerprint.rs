use assert_cmd::Command;
use tempfile::tempdir;

// `enprot fingerprint` exposes capability::KeyFp::from_pem so users
// can build trust_roots lists for policy files (TODO.finalize/26)
// without writing their own SHA3-256 computation.

#[test]
fn fingerprint_outputs_64_hex_chars_for_ed25519_pub() {
    let dir = tempdir().unwrap();
    let pub_pem = dir.path().join("pub.pem");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(&pub_pem)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout)
        .unwrap()
        .trim();
    assert_eq!(s.len(), 64, "fingerprint must be 64 hex chars (32 bytes)");
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be lowercase hex"
    );
}

#[test]
fn fingerprint_is_stable_across_invocations() {
    let dir = tempdir().unwrap();
    let pub_pem = dir.path().join("pub.pem");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    let out1 = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(&pub_pem)
        .assert()
        .success();
    let out2 = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(&pub_pem)
        .assert()
        .success();

    assert_eq!(
        std::str::from_utf8(&out1.get_output().stdout).unwrap(),
        std::str::from_utf8(&out2.get_output().stdout).unwrap(),
        "same pubkey must produce same fingerprint"
    );
}

#[test]
fn fingerprint_differs_for_different_keys() {
    let dir = tempdir().unwrap();
    let pub_a = dir.path().join("a.pub");
    let pub_b = dir.path().join("b.pub");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_a)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-pub"])
        .arg(&pub_b)
        .assert()
        .success();

    let out_a = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(&pub_a)
        .assert()
        .success();
    let out_b = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(&pub_b)
        .assert()
        .success();

    assert_ne!(
        std::str::from_utf8(&out_a.get_output().stdout).unwrap(),
        std::str::from_utf8(&out_b.get_output().stdout).unwrap(),
        "different pubkeys must produce different fingerprints"
    );
}

#[test]
fn fingerprint_rejects_missing_file() {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg("/nonexistent/path/pub.pem")
        .assert()
        .failure();
}
