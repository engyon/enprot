extern crate assert_cmd;
extern crate predicates;
extern crate tempfile;

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

use Fixture;

#[test]
fn encrypt_decrypt_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_stdin_pass() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg(&ept.path)
        .with_stdin()
        .buffer("password\r\npassword\r\n")
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_both_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007,GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password,GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-d")
        .arg("GEHEIM")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_geheim_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("GEHEIM")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
}

#[test]
fn encrypt_decrypt_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("GEHEIM")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
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

#[test]
fn encrypt_decrypt_agent007_default_pbkdf() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf-params") // just for speed
        .arg("m=8,t=1,p=1")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    // just make sure it selected argon2
    assert!(&fs::read_to_string(&ept.path)
        .unwrap()
        .contains("pbkdf:$argon2$"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_pbkdf2() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2")
        .arg("--pbkdf-params")
        .arg("i=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-pbkdf2.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_pbkdf2_sha512() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2")
        .arg("--pbkdf2-hash")
        .arg("sha512")
        .arg("--pbkdf-params")
        .arg("i=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-pbkdf2-sha512.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_pbkdf2_millis() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    {
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-e")
            .arg("Agent_007")
            .arg("--pbkdf")
            .arg("pbkdf2")
            .arg("--pbkdf-msec")
            .arg("50")
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&ept.path)
            .assert()
            .success();
        assert!(now.elapsed().as_millis() > 50);
    }
    {
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-e")
            .arg("Agent_007")
            .arg("--pbkdf")
            .arg("pbkdf2")
            .arg("--pbkdf-msec")
            .arg("10")
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&ept.path)
            .assert()
            .success();
        assert!(now.elapsed().as_millis() < 20);
    }
    assert!(&fs::read_to_string(&ept.path)
        .unwrap()
        .contains("$pbkdf2-sha256$"));
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_scrypt() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("scrypt")
        .arg("--pbkdf-params")
        .arg("ln=2,p=1,r=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-scrypt.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}
