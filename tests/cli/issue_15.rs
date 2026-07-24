use crate::Fixture;
use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

const PBKDF_OPTS: &[&str] = &[
    "--pbkdf",
    "pbkdf2-sha256",
    "--pbkdf-params",
    "i=1",
    "--pbkdf-salt",
    "0102030405060708",
    "--cipher",
    "aes-256-siv",
];

#[test]
fn nested_encrypt_alice() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    // encrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("alice")
        .args(PBKDF_OPTS)
        .arg("-k")
        .arg("alice=alicepass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-alice.ept").unwrap()
    );
    // decrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("alice")
        .arg("-k")
        .arg("alice=alicepass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15.ept").unwrap()
    );
}

#[test]
fn nested_encrypt_bob() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    // encrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("bob")
        .args(PBKDF_OPTS)
        .arg("-k")
        .arg("bob=bobpass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-bob.ept").unwrap()
    );
    // decrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("bob")
        .arg("-k")
        .arg("bob=bobpass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15.ept").unwrap()
    );
}

#[test]
fn nested_encrypt_alice_bob() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    // encrypt
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("-w")
        .arg("alice,bob")
        .args(PBKDF_OPTS)
        .arg("-k")
        .arg("alice=alicepass")
        .arg("-k")
        .arg("bob=bobpass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-alice-bob.ept").unwrap()
    );
    // decrypt (all at once)
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("decrypt")
        .arg("-w")
        .arg("alice,bob")
        .arg("-k")
        .arg("alice=alicepass")
        .arg("-k")
        .arg("bob=bobpass")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15.ept").unwrap()
    );
}

#[test]
fn nested_store_alice() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("test-data/issue-15.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("store")
        .arg("-w")
        .arg("alice")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-store-alice.ept").unwrap()
    );
    // fetch
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("fetch")
        .arg("-w")
        .arg("alice")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15.ept").unwrap()
    );
}

#[test]
fn nested_max_depth() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--max-depth=4")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--max-depth=3")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .failure();
}
