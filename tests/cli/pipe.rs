extern crate assert_cmd;
extern crate predicates;
extern crate tempfile;

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;

use Fixture;

#[test]
fn pipe_test_passthrough_default() {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .with_stdin()
        .buffer(fs::read_to_string("sample/test.ept").unwrap())
        .assert()
        .success()
        .stdout(fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap());
}

#[test]
fn pipe_test_passthrough() {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-")
        .with_stdin()
        .buffer(fs::read_to_string("sample/test.ept").unwrap())
        .assert()
        .success()
        .stdout(fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap());
}

#[test]
fn pipe_test_1() {
    let out = Fixture::blank("out.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-")
        .arg("-o")
        .arg(&out.path)
        .with_stdin()
        .buffer(fs::read_to_string("sample/test.ept").unwrap())
        .assert()
        .success()
        .stdout("");
    assert_eq!(
        &fs::read_to_string(&out.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap(),
    );
}

#[test]
fn pipe_test_2() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success()
        .stdout(fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap());
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn pipe_test_3() {
    let ept = Fixture::copy("sample/simple.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-")
        .arg(&ept.path)
        .with_stdin()
        .buffer(fs::read_to_string("sample/test.ept").unwrap())
        .assert()
        .success()
        .stdout(fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap());
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap()
    );
}
