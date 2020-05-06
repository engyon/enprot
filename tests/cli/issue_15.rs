use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

use Fixture;

fn encdec(args: &[&str]) -> assert_cmd::assert::Assert {
    let mut asdf = Command::cargo_bin("enprot").unwrap();
    asdf.arg("arg1");
    println!("{:#?}", asdf);
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-params")
        .arg("i=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("--cipher")
        .arg("aes-256-siv")
        .args(args)
        .assert()
}

#[test]
fn nested_encrypt_alice() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    // encrypt
    encdec(&[
        "-e",
        "alice",
        "-k",
        "alice=alicepass",
        &ept.path.to_str().unwrap(),
    ])
    .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-alice.ept").unwrap()
    );
    // decrypt
    encdec(&[
        "-d",
        "alice",
        "-k",
        "alice=alicepass",
        &ept.path.to_str().unwrap(),
    ])
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
    encdec(&[
        "-e",
        "bob",
        "-k",
        "bob=bobpass",
        &ept.path.to_str().unwrap(),
    ])
    .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-bob.ept").unwrap()
    );
    // decrypt
    encdec(&[
        "-d",
        "bob",
        "-k",
        "bob=bobpass",
        &ept.path.to_str().unwrap(),
    ])
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
    encdec(&[
        "-e",
        "alice,bob",
        "-k",
        "alice=alicepass,bob=bobpass",
        &ept.path.to_str().unwrap(),
    ])
    .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15-encrypt-alice-bob.ept").unwrap()
    );
    // decrypt (all at once)
    encdec(&[
        "-d",
        "alice,bob",
        "-k",
        "alice=alicepass,bob=bobpass",
        &ept.path.to_str().unwrap(),
    ])
    .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/issue-15.ept").unwrap()
    );
}

#[test]
fn nested_store_alice() {
    let ept = Fixture::copy("test-data/issue-15.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-s")
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
        .arg("-f")
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
        .arg(&ept.path)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--max-depth=3")
        .arg(&ept.path)
        .assert()
        .failure();
}
