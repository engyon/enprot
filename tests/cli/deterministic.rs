use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

// Issue #39: deterministic AES-GCM variants derive the IV from the
// plaintext via HKDF + HMAC, so encrypting the same plaintext twice
// with the same password produces byte-identical ciphertext. That
// unlocks CAS deduplication for encrypted segments.

fn encrypt_to(out: &std::path::Path, cipher: &str, pbkdf_salt: &str) {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-params")
        .arg("i=1000")
        .arg("--pbkdf-salt")
        .arg(pbkdf_salt)
        .arg("--cipher")
        .arg(cipher)
        .arg("-k")
        .arg("Agent_007=password")
        .arg("sample/test.ept")
        .arg("-o")
        .arg(out)
        .assert()
        .success();
}

#[test]
fn det_aes_256_gcm_is_deterministic() {
    let out1 = Fixture::blank("det1.ept");
    let out2 = Fixture::blank("det2.ept");
    encrypt_to(&out1.path, "aes-256-gcm-det", "0102030405060708");
    encrypt_to(&out2.path, "aes-256-gcm-det", "0102030405060708");
    assert_eq!(
        fs::read_to_string(&out1.path).unwrap(),
        fs::read_to_string(&out2.path).unwrap(),
        "deterministic variant must produce identical ciphertext for identical input"
    );

    // The cipher extfield records the det variant name so decrypt knows
    // it's plain AES-GCM underneath (IV is stored, not re-derived).
    let content = fs::read_to_string(&out1.path).unwrap();
    assert!(
        predicate::str::contains("cipher:aes-256-gcm-det$iv=").eval(&content),
        "cipher extfield should name the det variant; got: {}",
        content
    );
}

#[test]
fn det_aes_256_gcm_round_trips() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    let original = fs::read_to_string(&ept.path).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-params")
        .arg("i=1000")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("--cipher")
        .arg("aes-256-gcm-det")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&ept.path).unwrap(), original);
}

#[test]
fn det_aes_256_gcm_siv_is_deterministic() {
    let out1 = Fixture::blank("siv_det1.ept");
    let out2 = Fixture::blank("siv_det2.ept");
    encrypt_to(&out1.path, "aes-256-gcm-siv-det", "0102030405060708");
    encrypt_to(&out2.path, "aes-256-gcm-siv-det", "0102030405060708");
    assert_eq!(
        fs::read_to_string(&out1.path).unwrap(),
        fs::read_to_string(&out2.path).unwrap(),
    );
}

#[test]
fn det_distinct_from_nondet() {
    // Same password + plaintext + cipher backend, different IV derivation.
    // The det variant's ciphertext must differ from a random-IV encrypt.
    // (We're checking the IV really is derived differently — that the det
    // path didn't silently fall through to the random-IV path.)
    let det = Fixture::blank("det.ept");
    let rand = Fixture::blank("rand.ept");
    encrypt_to(&det.path, "aes-256-gcm-det", "0102030405060708");
    encrypt_to(&rand.path, "aes-256-gcm", "0102030405060708");
    // Random-IV variant's cipher: name doesn't have -det.
    let rand_content = fs::read_to_string(&rand.path).unwrap();
    assert!(predicate::str::contains("cipher:aes-256-gcm$iv=").eval(&rand_content));
    // And the two outputs differ in the actual ciphertext bytes.
    assert_ne!(fs::read_to_string(&det.path).unwrap(), rand_content,);
}

#[test]
fn det_aes_256_siv_rejected() {
    // AES-SIV is already deterministic by construction; -det suffix is
    // nonsensical and not in VALID_CIPHER_ALGS.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--cipher")
        .arg("aes-256-siv-det")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("sample/test.ept")
        .assert()
        .failure();
}
