extern crate assert_cmd;
extern crate predicates;
extern crate tempfile;

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
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
