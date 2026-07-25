// Integration tests for provenance manifest + attest (TODO.roadmap/51).

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
fn manifest_walks_tree_and_emits_include_per_file() {
    let proj = tempdir().unwrap();
    let cas = tempdir().unwrap();
    write(&proj.path().join("a.txt"), "alpha");
    write(&proj.path().join("sub/b.txt"), "beta");

    let manifest_path = proj.path().join("manifest.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(proj.path())
        .args(["manifest"])
        .arg(proj.path())
        .args(["-c"])
        .arg(cas.path())
        .args(["--output"])
        .arg(&manifest_path)
        .assert()
        .success();

    let body = fs::read_to_string(&manifest_path).unwrap();
    assert!(body.contains("INCLUDE"), "got: {body}");
    assert!(body.contains("# path: a.txt"));
    assert!(body.contains("# path: sub/b.txt"));
    // CAS directory should contain 2 hash-named files.
    let cas_entries = std::fs::read_dir(cas.path()).unwrap().count();
    assert_eq!(cas_entries, 2);
}

#[test]
fn manifest_to_stdout_works() {
    let proj = tempdir().unwrap();
    let cas = tempdir().unwrap();
    write(&proj.path().join("a.txt"), "alpha");

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(["manifest"])
        .arg(proj.path())
        .args(["-c"])
        .arg(cas.path())
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("INCLUDE"));
}

#[test]
fn attest_signs_manifest_and_verify_chain_accepts_it() {
    let proj = tempdir().unwrap();
    let cas = tempdir().unwrap();
    write(&proj.path().join("a.txt"), "alpha");

    let manifest_path = proj.path().join("manifest.ept");
    let builder_priv = proj.path().join("builder.pem");
    let builder_pub = proj.path().join("builder.pub");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519"])
        .args(["--out-priv", builder_priv.to_str().unwrap()])
        .args(["--out-pub", builder_pub.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["manifest"])
        .arg(proj.path())
        .args(["-c"])
        .arg(cas.path())
        .args(["--output"])
        .arg(&manifest_path)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["attest"])
        .args(["--signer", builder_priv.to_str().unwrap()])
        .arg(&manifest_path)
        .assert()
        .success();

    let body = fs::read_to_string(&manifest_path).unwrap();
    assert!(body.contains("CHAIN"), "attest should append CHAIN: {body}");

    // verify-chain accepts the manifest with the builder's pubkey.
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain"])
        .args(["--trust-root", builder_pub.to_str().unwrap()])
        .arg(&manifest_path)
        .assert()
        .success();
}

#[test]
fn attest_detects_tampering_after_signature() {
    let proj = tempdir().unwrap();
    let cas = tempdir().unwrap();
    write(&proj.path().join("a.txt"), "alpha");

    let manifest_path = proj.path().join("manifest.ept");
    let builder_priv = proj.path().join("builder.pem");
    let builder_pub = proj.path().join("builder.pub");

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519"])
        .args(["--out-priv", builder_priv.to_str().unwrap()])
        .args(["--out-pub", builder_pub.to_str().unwrap()])
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["manifest"])
        .arg(proj.path())
        .args(["-c"])
        .arg(cas.path())
        .args(["--output"])
        .arg(&manifest_path)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["attest"])
        .args(["--signer", builder_priv.to_str().unwrap()])
        .arg(&manifest_path)
        .assert()
        .success();

    // Tamper: change the path comment.
    let mut body = fs::read_to_string(&manifest_path).unwrap();
    body = body.replace("# path: a.txt", "# path: tampered.txt");
    fs::write(&manifest_path, body).unwrap();

    // verify-chain must fail because the payload_hash no longer
    // matches what the signature committed to.
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["verify-chain"])
        .args(["--trust-root", builder_pub.to_str().unwrap()])
        .arg(&manifest_path)
        .assert()
        .failure();
}
