// Integration tests for CAS-referenced default (TODO.roadmap/42).
//
// `enprot encrypt` defaults to producing `STORED ct <hash>` blocks
// when a CAS dir is explicitly supplied. `--inline` restores the old
// inline DATA behavior. Without `-c`, encryption stays inline (stdin
// pipeline carve-out).

use crate::Fixture;
use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn encrypt_with_cas_produces_stored_ct_by_default() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();

    let s = fs::read_to_string(&ept.path).unwrap();
    // The writer inlines the CAS hash into the ENCRYPTED directive:
    //   // <( ENCRYPTED Agent_007 <hash> pbkdf:... )>
    // (no END Agent_007 — the hash IS the content).
    assert!(
        s.contains("ENCRYPTED Agent_007 ") && !s.contains("END Agent_007"),
        "default encrypt with -c should inline a CAS hash on ENCRYPTED; got:\n{s}"
    );
    assert!(
        !s.contains("DATA "),
        "default encrypt should not emit inline DATA; got:\n{s}"
    );
}

#[test]
fn encrypt_inline_flag_restores_inline_data() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("--inline")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();

    let s = fs::read_to_string(&ept.path).unwrap();
    assert!(
        s.contains("DATA "),
        "--inline should emit inline DATA; got:\n{s}"
    );
    assert!(
        s.contains("END Agent_007"),
        "--inline should produce ENCRYPTED...END block; got:\n{s}"
    );
}

#[test]
fn encrypt_without_cas_stays_inline() {
    // No -c: stdin-pipeline carve-out. Even though `.` exists, the
    // default is inline because the caller didn't ask for CAS. We run
    // inside a tempdir so any incidental CAS writes land there, not
    // in the repo root.
    let cwd = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(cwd.path())
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();

    let s = fs::read_to_string(&ept.path).unwrap();
    assert!(
        s.contains("DATA "),
        "no -c should default to inline; got:\n{s}"
    );
}

#[test]
fn cas_dedup_same_plaintext_password_reuses_hash() {
    let casdir = tempdir().unwrap();

    // First encryption.
    let ept1 = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept1.path)
        .assert()
        .success();
    let s1 = fs::read_to_string(&ept1.path).unwrap();
    let hash1 = extract_encrypted_hash(&s1).expect("first run should inline CAS hash");

    // Second encryption with the same plaintext+password.
    let ept2 = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept2.path)
        .assert()
        .success();
    let s2 = fs::read_to_string(&ept2.path).unwrap();
    let hash2 = extract_encrypted_hash(&s2).expect("second run should inline CAS hash");

    assert_eq!(
        hash1, hash2,
        "same plaintext+password should reuse CAS hash"
    );
}

/// Pull the first 64-hex-char CAS hash out of an ENCRYPTED line.
fn extract_encrypted_hash(s: &str) -> Option<String> {
    let line = s.lines().find(|l| l.contains("ENCRYPTED Agent_007 "))?;
    let hex: String = line
        .chars()
        .collect::<String>()
        .split_whitespace()
        .find(|tok| tok.len() == 64 && tok.chars().all(|c| c.is_ascii_hexdigit()))?
        .to_string();
    Some(hex)
}
