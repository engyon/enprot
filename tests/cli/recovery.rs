// Integration tests for escrow-mode encryption (TODO.complete/59):
// `--recovery-key` gives an Encrypted block two independent
// decryption paths — the password and any recovery privkey.

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
        // `enprot keygen` only emits signature keys; KEM keys come
        // from the library surface (same one `--recipients` uses).
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

fn escrow_doc(path: &std::path::Path, recovery_pub: &std::path::Path) {
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
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("--recovery-key")
        .arg(recovery_pub)
        .arg(path)
        .assert()
        .success();
    let content = fs::read_to_string(path).unwrap();
    assert!(content.contains("recovery:mlkem:"), "escrow fields missing");
    assert!(content.contains("pw-wrap:"), "pw-wrap field missing");
}

#[test]
fn escrow_decrypts_with_password_and_with_recovery_key() {
    let rec = Keys::mlkem("rec");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    escrow_doc(&file, &rec.pub_path());

    // Path 1: the ordinary password (in-place rewrite).
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&file)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("secret agent business"),
        "password path must restore the plaintext in place"
    );

    // Path 2: the recovery privkey, no password at all.
    let file2 = doc.path().join("doc-key.ept");
    escrow_doc(&file2, &rec.pub_path());
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--key-file")
        .arg(rec.priv_path())
        .arg(&file2)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&file2)
            .unwrap()
            .contains("secret agent business"),
        "recovery-key path must restore the plaintext in place"
    );
}

#[test]
fn escrow_wrong_password_fails_cleanly() {
    let rec = Keys::mlkem("rec");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    escrow_doc(&file, &rec.pub_path());

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=wrong-password")
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains("AEAD decrypt failed"));

    // Neither password nor key supplied: actionable error, no prompt.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains("--key-file"));
}

#[test]
fn escrow_with_multiple_recovery_keys_any_privkey_suffices() {
    let rec1 = Keys::mlkem("rec1");
    let rec2 = Keys::mlkem("rec2");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");

    fs::write(
        &file,
        "// <( BEGIN Agent_007 )>\nsecret agent business\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("--recovery-key")
        .arg(rec1.pub_path())
        .arg("--recovery-key")
        .arg(rec2.pub_path())
        .arg(&file)
        .assert()
        .success();
    let content = fs::read_to_string(&file).unwrap();
    assert!(content.matches("recovery-kem-mlkem-").count() >= 2);

    for (i, priv_key) in [rec1.priv_path(), rec2.priv_path()].into_iter().enumerate() {
        let f = doc.path().join(format!("doc-{i}.ept"));
        fs::write(
            &f,
            "// <( BEGIN Agent_007 )>\nsecret agent business\n// <( END Agent_007 )>\n",
        )
        .unwrap();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("encrypt")
            .arg("-w")
            .arg("Agent_007")
            .arg("-k")
            .arg("Agent_007=password")
            .arg("--cipher")
            .arg("aes-256-siv")
            .arg("--recovery-key")
            .arg(rec1.pub_path())
            .arg("--recovery-key")
            .arg(rec2.pub_path())
            .arg(&f)
            .assert()
            .success();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("decrypt")
            .arg("-w")
            .arg("Agent_007")
            .arg("--key-file")
            .arg(&priv_key)
            .arg(&f)
            .assert()
            .success();
        assert!(
            fs::read_to_string(&f)
                .unwrap()
                .contains("secret agent business")
        );
    }
}

#[test]
fn escrow_refused_with_det_cipher() {
    let rec = Keys::mlkem("rec");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    fs::write(
        &file,
        "// <( BEGIN Agent_007 )>\nsecret\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-gcm-det")
        .arg("--recovery-key")
        .arg(rec.pub_path())
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains("incompatible"));
}

#[test]
fn password_mode_unaffected_without_recovery_key() {
    // No --recovery-key: the wire format is exactly the legacy one.
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    fs::write(
        &file,
        "// <( BEGIN Agent_007 )>\nsecret agent business\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg(&file)
        .assert()
        .success();
    let content = fs::read_to_string(&file).unwrap();
    assert!(!content.contains("recovery:"), "no escrow fields expected");
    assert!(!content.contains("pw-wrap:"), "no pw-wrap expected");
}
