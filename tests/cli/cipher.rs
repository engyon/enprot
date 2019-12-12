use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

use Fixture;

#[test]
fn encrypt_gcm_random_iv() {
    let epts = &[
        Fixture::copy("sample/simple.ept"),
        Fixture::copy("sample/simple.ept"),
    ];

    for ept in epts {
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("--encrypt")
            .arg("Agent_007")
            .arg("--pbkdf")
            .arg("argon2")
            .arg("--pbkdf-params")
            .arg("t=1,p=1,m=16")
            .arg("--pbkdf-salt")
            .arg("0102030405060708")
            .arg("-k")
            .arg("Agent_007=password")
            .arg("--cipher")
            .arg("aes-256-gcm")
            .arg(&ept.path)
            .assert()
            .success();
        assert!(&fs::read_to_string(&ept.path)
            .unwrap()
            .contains("aes-256-gcm"));
        let out = Fixture::blank("out.ept");
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-d")
            .arg("Agent_007")
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&ept.path)
            .arg("-o")
            .arg(&out.path)
            .assert()
            .success();
        // make sure we can decrypt correctly
        assert_eq!(
            &fs::read_to_string(&out.path).unwrap(),
            &fs::read_to_string(&ept.source).unwrap()
        );
    }
    // should be random IVs so these should not match
    assert_ne!(
        &fs::read_to_string(&epts[0].path).unwrap(),
        &fs::read_to_string(&epts[1].path).unwrap(),
    );
}

#[test]
fn encrypt_gcm() {
    let ept = Fixture::copy("sample/simple.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("argon2")
        .arg("--pbkdf-params")
        .arg("t=1,p=1,m=16")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-gcm")
        .arg("--cipher-iv")
        .arg("010203040506070809101112")
        .arg(&ept.path)
        .assert()
        .success();
    assert!(&fs::read_to_string(&ept.path)
        .unwrap()
        .contains("aes-256-gcm"));
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007-gcm.ept").unwrap()
    );
    // decrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    // make sure we can decrypt correctly
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
}

// IV should not be supplied for aes-256-siv
#[test]
fn encrypt_siv_iv() {
    let ept = Fixture::copy("sample/simple.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("argon2")
        .arg("--pbkdf-params")
        .arg("t=1,p=1,m=16")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("--cipher-iv")
        .arg("010203040506070809101112")
        .arg(&ept.path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("IV was supplied"));
}

#[test]
fn encrypt_siv() {
    let ept = Fixture::copy("sample/simple.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap(),
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
}
