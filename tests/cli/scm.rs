// Integration tests for the supply-chain manifest CLI (TODO.roadmap/52).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write(path: &std::path::Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

#[test]
fn scm_init_writes_empty_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("m.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "init"])
        .arg(&manifest)
        .assert()
        .success();
    let body = fs::read_to_string(&manifest).unwrap();
    assert!(body.contains("supply-chain manifest"));
}

#[test]
fn scm_add_appends_to_manifest() {
    let dir = tempdir().unwrap();
    let cas = tempdir().unwrap();
    let manifest = dir.path().join("m.ept");
    write(&dir.path().join("a.txt"), "alpha");

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["init"])
        .arg(&manifest)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["add"])
        .arg(&manifest)
        .arg(dir.path().join("a.txt"))
        .assert()
        .success();

    let body = fs::read_to_string(&manifest).unwrap();
    assert!(body.contains("INCLUDE"), "got: {body}");
}

#[test]
fn scm_deps_appends_cargo_dependencies() {
    let dir = tempdir().unwrap();
    let cas = tempdir().unwrap();
    let manifest = dir.path().join("m.ept");
    let cargo_toml = dir.path().join("Cargo.toml");
    write(
        &cargo_toml,
        r#"
[package]
name = "demo"
[dependencies]
serde = "1.0"
hex = "0.4"
"#,
    );

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["init"])
        .arg(&manifest)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["deps"])
        .arg(&manifest)
        .arg(&cargo_toml)
        .assert()
        .success();

    let body = fs::read_to_string(&manifest).unwrap();
    assert!(body.contains("# dep: serde=1.0"), "got: {body}");
    assert!(body.contains("# dep: hex=0.4"));
}

#[test]
fn scm_attest_signs_then_verify_accepts() {
    let dir = tempdir().unwrap();
    let cas = tempdir().unwrap();
    let manifest = dir.path().join("m.ept");
    let vendor_priv = dir.path().join("vendor.pem");
    let vendor_pub = dir.path().join("vendor.pub");
    write(&dir.path().join("a.txt"), "alpha");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519"])
        .args(["--out-priv", vendor_priv.to_str().unwrap()])
        .args(["--out-pub", vendor_pub.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["init"])
        .arg(&manifest)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["add"])
        .arg(&manifest)
        .arg(dir.path().join("a.txt"))
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["attest", "--signer"])
        .arg(&vendor_priv)
        .arg(&manifest)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["scm", "-c"])
        .arg(cas.path())
        .args(["verify", "--trust-root"])
        .arg(&vendor_pub)
        .arg(&manifest)
        .assert()
        .success();
}

#[test]
fn scm_diff_reports_changes_between_manifests() {
    let dir = tempdir().unwrap();
    let cas = tempdir().unwrap();
    let old = dir.path().join("old.ept");
    let new = dir.path().join("new.ept");

    let old_proj = dir.path().join("old_proj");
    let new_proj = dir.path().join("new_proj");
    fs::create_dir_all(&old_proj).unwrap();
    fs::create_dir_all(&new_proj).unwrap();
    write(&old_proj.join("a.txt"), "alpha");
    write(&old_proj.join("b.txt"), "beta");
    write(&new_proj.join("a.txt"), "alpha-modified");
    write(&new_proj.join("c.txt"), "gamma");

    // Build both manifests with `enprot manifest`, then diff them.
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["manifest"])
        .arg(&old_proj)
        .args(["-c"])
        .arg(cas.path())
        .args(["--output"])
        .arg(&old)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["manifest"])
        .arg(&new_proj)
        .args(["-c"])
        .arg(cas.path())
        .args(["--output"])
        .arg(&new)
        .assert()
        .success();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(["scm", "diff"])
        .arg(&old)
        .arg(&new)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("+ path:"), "got: {s}");
    assert!(s.contains("- path:"), "got: {s}");
    assert!(s.contains("~ path:"), "got: {s}");
}
