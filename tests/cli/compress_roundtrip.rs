use crate::Fixture;
use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn compress_encrypt_decrypt_round_trip() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    // Encrypt with --compress
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-k")
        .arg("Agent_007=password123")
        .arg("encrypt")
        .arg("--compress")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-msec")
        .arg("10")
        .arg(&ept.path)
        .assert()
        .success();

    // Verify the encrypt produced output
    let content = fs::read_to_string(&ept.path).unwrap();
    assert!(
        content.contains("ENCRYPTED"),
        "file should have ENCRYPTED block after encrypt"
    );

    // Decrypt — should recover the original plaintext
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-k")
        .arg("Agent_007=password123")
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();

    // The decrypted content should match the original sample file
    let decrypted = fs::read_to_string(&ept.path).unwrap();
    let original = fs::read_to_string(&ept.source).unwrap();
    assert_eq!(
        decrypted, original,
        "decrypt(compress(encrypt(pt))) == pt — round-trip must recover original"
    );
}

#[test]
fn compress_without_compress_flag_still_round_trips() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    // Encrypt WITHOUT --compress
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-k")
        .arg("Agent_007=password123")
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-msec")
        .arg("10")
        .arg(&ept.path)
        .assert()
        .success();

    // Decrypt — should recover original
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-k")
        .arg("Agent_007=password123")
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();

    let decrypted = fs::read_to_string(&ept.path).unwrap();
    let original = fs::read_to_string(&ept.source).unwrap();
    assert_eq!(
        decrypted, original,
        "round-trip without compression must work"
    );
}
