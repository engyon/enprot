// Integration tests for `enprot rotate` (TODO 59's key-lifecycle gap):
// re-wrap escrow blocks' CEK under new key material without touching
// the payload ciphertext.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

struct Keys {
    dir: TempDir,
    name: &'static str,
}

impl Keys {
    fn mlkem(name: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let k = Keys { dir, name };
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, pub_pem) =
            enprot::pki::kem_keygen(enprot::pki::KemAlgKind::MlKem, &mut rng).unwrap();
        fs::write(k.priv_path(), priv_pem).unwrap();
        fs::write(k.pub_path(), pub_pem).unwrap();
        k
    }

    fn priv_path(&self) -> std::path::PathBuf {
        self.dir.path().join(format!("{}_priv.pem", self.name))
    }

    fn pub_path(&self) -> std::path::PathBuf {
        self.dir.path().join(format!("{}_pub.pem", self.name))
    }
}

fn escrow_doc(path: &std::path::Path, recovery_pub: &std::path::Path) -> String {
    fs::write(
        path,
        "// <( BEGIN Agent_007 )>\nsecret agent business\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=old-password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("--recovery-key")
        .arg(recovery_pub)
        .arg(path)
        .assert()
        .success();
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("recovery:mlkem:"), "escrow fields missing");
    content
}

#[test]
fn rotate_to_new_password_and_recovery_key() {
    let old_rec = Keys::mlkem("old");
    let new_rec = Keys::mlkem("new");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    let before = escrow_doc(&file, &old_rec.pub_path());

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-k")
        .arg("Agent_007=old-password")
        .arg("rotate")
        .arg("--new-password")
        .arg("new-password")
        .arg("--recovery-key")
        .arg(new_rec.pub_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("rotated 1 escrow block"));

    // The payload ciphertext (DATA lines) is byte-identical: only the
    // key-material extfields changed.
    let after = fs::read_to_string(&file).unwrap();
    let before_data: Vec<&str> = before.lines().filter(|l| l.contains("DATA")).collect();
    let after_data: Vec<&str> = after.lines().filter(|l| l.contains("DATA")).collect();
    assert_eq!(before_data, after_data, "payload must be unchanged");

    // Old password no longer decrypts.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=old-password")
        .arg(&file)
        .assert()
        .failure();

    // New password decrypts.
    let dec = doc.path().join("dec.ept");
    fs::copy(&file, &dec).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=new-password")
        .arg(&dec)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&dec)
            .unwrap()
            .contains("secret agent business")
    );

    // New recovery key decrypts.
    let dec2 = doc.path().join("dec2.ept");
    fs::copy(&file, &dec2).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--key-file")
        .arg(new_rec.priv_path())
        .arg(&dec2)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&dec2)
            .unwrap()
            .contains("secret agent business")
    );
}

#[test]
fn rotate_via_old_recovery_key_without_password() {
    let old_rec = Keys::mlkem("old");
    let new_rec = Keys::mlkem("new2");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    escrow_doc(&file, &old_rec.pub_path());

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("rotate")
        .arg("--key-file")
        .arg(old_rec.priv_path())
        .arg("--new-password")
        .arg("rotated-pw")
        .arg("--recovery-key")
        .arg(new_rec.pub_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("rotated 1 escrow block"));

    let dec = doc.path().join("dec.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=rotated-pw")
        .arg(&file)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("secret agent business")
    );
    let _ = dec;
}

#[test]
fn rotate_finds_escrow_block_nested_in_begin_end() {
    let rec = Keys::mlkem("nested");
    let new_rec = Keys::mlkem("nested-new");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("nested.ept");
    // The escrow block sits INSIDE an outer BEGIN/END segment, so
    // the ENCRYPTED node is a child of a BeginEnd node: rotation
    // only finds it if the walk descends.
    fs::write(
        &file,
        "// <( BEGIN outer )>\n// <( BEGIN inner )>\nsecret nested business\n// <( END inner )>\n// <( END outer )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("inner")
        .arg("-k")
        .arg("inner=old-password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("--recovery-key")
        .arg(rec.pub_path())
        .arg(&file)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-k")
        .arg("inner=old-password")
        .arg("rotate")
        .arg("--new-password")
        .arg("new-password")
        .arg("--recovery-key")
        .arg(new_rec.pub_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("rotated 1 escrow block"));

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("inner")
        .arg("-k")
        .arg("inner=new-password")
        .arg(&file)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("secret nested business")
    );
}

#[test]
fn rotate_without_credentials_fails_with_actionable_error() {
    let rec = Keys::mlkem("rec");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    escrow_doc(&file, &rec.pub_path());

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("rotate")
        .arg("--new-password")
        .arg("x")
        .arg("--recovery-key")
        .arg(rec.pub_path())
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains("current WORD password"));
}

#[test]
fn rotate_leaves_non_escrow_blocks_untouched() {
    let rec = Keys::mlkem("rec");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("plain.ept");
    // No --recovery-key: legacy password mode, no recovery: field.
    fs::write(&file, "// <( BEGIN W )>\nplain secret\n// <( END W )>\n").unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("W")
        .arg("-k")
        .arg("W=pw")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg(&file)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-k")
        .arg("W=pw")
        .arg("rotate")
        .arg("--new-password")
        .arg("whatever")
        .arg("--recovery-key")
        .arg(rec.pub_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("no escrow-mode blocks"));

    // The file still decrypts with the ORIGINAL password.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("W")
        .arg("-k")
        .arg("W=pw")
        .arg(&file)
        .assert()
        .success();
}
