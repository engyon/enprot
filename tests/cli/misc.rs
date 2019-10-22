extern crate assert_cmd;
extern crate predicates;
extern crate tempfile;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

use Fixture;

#[test]
fn help_produces_usage() {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn success_on_no_operation() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg(&ept.path)
        .assert()
        .success();
    // file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn verbosity() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg(&ept.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("LEFT_SEP").not());
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-v")
        .arg(&ept.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("LEFT_SEP"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--verbose")
        .arg(&ept.path)
        .assert()
        .success()
        .stdout(predicate::str::contains("LEFT_SEP"));
    // file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn output() {
    let ept = Fixture::copy("sample/test.ept");
    let output = Fixture::blank("out.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg(&output.path)
        .assert()
        .success();
    // original file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&output.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
}
