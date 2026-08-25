// Integration tests for `enprot migrate-keys` (TODO.complete/58) —
// the post-quantum anchor migration path.
//
// Every test drives the real binary end to end: keygen → anchor →
// migrate → verify-chain, against real Ed25519 / ML-DSA /
// composite keys (no mocks).

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

struct Keys {
    dir: TempDir,
    name: &'static str,
}

impl Keys {
    /// Generate a keypair via `enprot keygen` into a fresh tempdir.
    fn generate(name: &'static str, alg: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let k = Keys { dir, name };
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("keygen")
            .arg(alg)
            .arg("--out-priv")
            .arg(k.priv_path())
            .arg("--out-pub")
            .arg(k.pub_path())
            .assert()
            .success();
        k
    }

    fn priv_path(&self) -> std::path::PathBuf {
        self.dir.path().join(format!("{}_priv.pem", self.name))
    }

    fn pub_path(&self) -> std::path::PathBuf {
        self.dir.path().join(format!("{}_pub.pem", self.name))
    }
}

/// A minimal EPT doc with one segment, anchored by `signer_priv`.
fn anchored_doc(path: &std::path::Path, signer_priv: &std::path::Path) {
    fs::write(
        path,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--anchor")
        .arg("--signer")
        .arg(signer_priv)
        .arg("passthrough")
        .arg(path)
        .assert()
        .success();
}

fn signer_of(path: &std::path::Path) -> String {
    let content = fs::read_to_string(path).unwrap();
    content
        .lines()
        .find(|l| l.contains("CHAIN"))
        .and_then(|l| l.split_whitespace().find(|f| f.starts_with("signer:")))
        .expect("a CHAIN signer field")
        .to_string()
}

fn payload_of(path: &std::path::Path) -> String {
    let content = fs::read_to_string(path).unwrap();
    content
        .lines()
        .find(|l| l.contains("CHAIN"))
        .and_then(|l| l.split_whitespace().find(|f| f.starts_with("payload:")))
        .expect("a CHAIN payload field")
        .to_string()
}

#[test]
fn migrate_ed25519_to_mldsa_swaps_signer_and_verifies() {
    let old = Keys::generate("old", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    anchored_doc(&file, &old.priv_path());

    let before = signer_of(&file);
    assert!(before.starts_with("signer:ed25519:"), "got {before}");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(new.priv_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("migrated 1 anchor(s)"));

    let after = signer_of(&file);
    assert!(after.starts_with("signer:mldsa:"), "got {after}");

    // The new trust root verifies; the old one no longer does.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(new.pub_path())
        .arg(&file)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(old.pub_path())
        .arg(&file)
        .assert()
        .failure();
}

#[test]
fn migrate_preserves_payload_hash() {
    let old = Keys::generate("old", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    anchored_doc(&file, &old.priv_path());

    let payload_before = payload_of(&file);
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(new.priv_path())
        .arg(&file)
        .assert()
        .success();
    assert_eq!(payload_before, payload_of(&file));
}

#[test]
fn migrate_is_reversible() {
    let old = Keys::generate("old", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    anchored_doc(&file, &old.priv_path());

    let migrate = |from: &str, to: &str, old_pub: &std::path::Path, new_priv: &std::path::Path| {
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("migrate-keys")
            .arg("--from")
            .arg(from)
            .arg("--to")
            .arg(to)
            .arg("--old-key")
            .arg(old_pub)
            .arg("--new-key")
            .arg(new_priv)
            .arg(&file)
            .assert()
            .success();
    };

    migrate("ed25519", "mldsa", &old.pub_path(), &new.priv_path());
    migrate("mldsa", "ed25519", &new.pub_path(), &old.priv_path());

    assert!(signer_of(&file).starts_with("signer:ed25519:"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(old.pub_path())
        .arg(&file)
        .assert()
        .success();
}

#[test]
fn tampered_anchor_refuses_and_leaves_file_untouched() {
    let old = Keys::generate("old", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    anchored_doc(&file, &old.priv_path());

    // Corrupt one hex digit of the signature.
    let content = fs::read_to_string(&file).unwrap();
    let sig_pos = content.find("sig:").expect("a sig field");
    let mut bytes = content.into_bytes();
    let target = sig_pos + 4;
    bytes[target] = if bytes[target] == b'0' { b'1' } else { b'0' };
    fs::write(&file, bytes).unwrap();

    let before = fs::read(&file).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(new.priv_path())
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains("signature verification failed"));
    assert_eq!(before, fs::read(&file).unwrap(), "file must be untouched");
}

#[test]
fn foreign_signer_descendant_refuses() {
    let old = Keys::generate("old", "ed25519");
    let other = Keys::generate("other", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");

    // Anchor 1 by `old`; anchor 2 by `other`, parented on anchor 1.
    fs::write(
        &file,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    for signer in [&old.priv_path(), &other.priv_path()] {
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("--anchor")
            .arg("--signer")
            .arg(signer)
            .arg("passthrough")
            .arg(&file)
            .assert()
            .success();
    }

    let before = fs::read(&file).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(new.priv_path())
        .arg(&file)
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "references a migrated parent but is signed by a different key",
        ));
    assert_eq!(before, fs::read(&file).unwrap(), "file must be untouched");
}

#[test]
fn chain_migration_rewires_parents() {
    let old = Keys::generate("old", "ed25519");
    let new = Keys::generate("new", "mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");

    // Two anchors by the same key: the second parents on the first.
    fs::write(
        &file,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    for _ in 0..2 {
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("--anchor")
            .arg("--signer")
            .arg(old.priv_path())
            .arg("passthrough")
            .arg(&file)
            .assert()
            .success();
    }

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(new.priv_path())
        .arg(&file)
        .assert()
        .success()
        .stdout(predicates::str::contains("migrated 2 anchor(s)"));

    // The whole rewired DAG verifies under the new key: both parent
    // references resolve to the re-signed anchors' new hashes.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(new.pub_path())
        .arg(&file)
        .assert()
        .success();
}

#[test]
fn migrate_ed25519_to_composite() {
    let old = Keys::generate("old", "ed25519");
    let comp = Keys::generate("comp", "composite-ed25519-mldsa");
    let doc = tempfile::tempdir().unwrap();
    let file = doc.path().join("doc.ept");
    anchored_doc(&file, &old.priv_path());

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("composite-ed25519-mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(comp.priv_path())
        .arg(&file)
        .assert()
        .success();
    assert!(signer_of(&file).starts_with("signer:composite-ed25519-mldsa:"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("verify-chain")
        .arg("--trust-root")
        .arg(comp.pub_path())
        .arg(&file)
        .assert()
        .success();
}

#[test]
fn same_from_and_to_rejected() {
    let old = Keys::generate("old", "ed25519");
    let doc = tempfile::tempdir().unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("ed25519")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(old.priv_path())
        .arg(doc.path().join("doc.ept"))
        .assert()
        .failure()
        .stderr(predicates::str::contains("--from and --to are both"));
}

#[test]
fn stdin_input_rejected() {
    let old = Keys::generate("old", "ed25519");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("migrate-keys")
        .arg("--from")
        .arg("ed25519")
        .arg("--to")
        .arg("mldsa")
        .arg("--old-key")
        .arg(old.pub_path())
        .arg("--new-key")
        .arg(old.priv_path())
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains("stdin"));
}
