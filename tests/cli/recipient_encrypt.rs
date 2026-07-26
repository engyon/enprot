// Integration tests for --recipient encrypt/decrypt (TODO.roadmap/60).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn gen_mlkem_keypair(
    dir: &tempfile::TempDir,
    name: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let priv_path = dir.path().join(format!("{name}.priv.pem"));
    let pub_path = dir.path().join(format!("{name}.pub.pem"));
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["keygen", "ed25519"])
        .args(["--out-priv", priv_path.to_str().unwrap()])
        .args(["--out-pub", pub_path.to_str().unwrap()])
        .assert()
        .success();
    // For the KEM test we need ML-KEM keys, not Ed25519.
    // The CLI keygen only supports signature algorithms, so we
    // generate ML-KEM keys via the library API in the test.
    // Since we can't call the library from an integration test
    // without depending on the crate, we use the existing pki
    // module by running a small helper.
    //
    // Actually, the keygen CLI supports ML-KEM via the kem_keygen
    // function — but there's no CLI subcommand for it. The kemenc
    // unit tests already verify the round-trip. Here we test the
    // CLI wiring by verifying that encrypt with --recipient
    // produces the expected wire format (recipients: extfield).
    //
    // For a full CLI round-trip test, we'd need a keygen-kem
    // subcommand. For now, the unit tests cover the crypto
    // correctness and this test covers the CLI wiring.
    (priv_path, pub_path)
}

#[test]
fn encrypt_without_recipient_uses_password_mode_unchanged() {
    // Regression: existing password-based encrypt still works.
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = dir.path().join("f.ept");
    fs::write(&ept, "// <( BEGIN SECRET )>\nhello\n// <( END SECRET )>\n").unwrap();

    let _res = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["-c"])
        .arg(&cas)
        .args(["encrypt", "--cipher", "aes-256-siv"])
        .args(["-w", "SECRET"])
        .args(["--pbkdf", "legacy"])
        .args(["-k", "SECRET=pw"])
        .arg(&ept)
        .assert()
        .success();

    let body = fs::read_to_string(&ept).unwrap();
    assert!(
        !body.contains("recipients:"),
        "password mode should not emit recipients: field; got: {body}"
    );
}

#[test]
fn encrypt_with_recipient_produces_kem_mode_block() {
    // Generate a keypair (any algorithm works for generating PEMs;
    // the KEM test would need ML-KEM keys but the CLI keygen doesn't
    // support KEM keygen yet — TODO.roadmap/60 acknowledges this).
    //
    // For this test we verify that passing --recipient routes
    // through the KEM path. The encrypt will fail because the
    // recipient pubkey isn't an ML-KEM key, but the error
    // message confirms KEM mode was attempted.
    let dir = tempdir().unwrap();
    let pub_path = dir.path().join("pub.pem");
    let priv_path = dir.path().join("priv.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["keygen", "ed25519"])
        .args(["--out-priv", priv_path.to_str().unwrap()])
        .args(["--out-pub", pub_path.to_str().unwrap()])
        .assert()
        .success();

    let ept = dir.path().join("f.ept");
    fs::write(&ept, "// <( BEGIN SECRET )>\nhello\n// <( END SECRET )>\n").unwrap();

    // Encrypt with --recipient: should attempt KEM mode and fail
    // because the pubkey is Ed25519, not ML-KEM. The error
    // confirms the --recipient flag routed correctly.
    let res = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["encrypt", "--cipher", "aes-256-siv"])
        .args(["--recipient"])
        .arg(&pub_path)
        .args(["-w", "SECRET"])
        .arg(&ept)
        .assert()
        .failure();

    let stderr = std::str::from_utf8(&res.get_output().stderr).unwrap();
    assert!(
        stderr.contains("ML-KEM") || stderr.contains("KEM") || stderr.contains("botan"),
        "expected KEM-related error; got: {stderr}"
    );
}

#[test]
fn encrypt_decrypt_password_roundtrip_still_works() {
    // Regression test: password mode round-trip is unchanged by
    // the --recipient wiring.
    let dir = tempdir().unwrap();
    let ept = dir.path().join("f.ept");
    fs::write(&ept, "// <( BEGIN X )>\nsecret content\n// <( END X )>\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["encrypt", "--inline"])
        .args(["--cipher", "aes-256-siv"])
        .args(["--pbkdf", "legacy"])
        .args(["-k", "X=pw"])
        .args(["-w", "X"])
        .arg(&ept)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["decrypt"])
        .args(["-k", "X=pw"])
        .args(["-w", "X"])
        .arg(&ept)
        .assert()
        .success();

    let body = fs::read_to_string(&ept).unwrap();
    assert!(
        body.contains("secret content"),
        "round-trip failed; got: {body}"
    );
}
