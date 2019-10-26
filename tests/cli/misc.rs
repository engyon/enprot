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
        .stdout(predicate::str::contains("USAGE:"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"));
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
        .arg("--pbkdf")
        .arg("legacy")
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

#[test]
fn output_multiple() {
    let ept1 = Fixture::copy("sample/test.ept");
    let ept2 = Fixture::copy("sample/simple.ept");
    let ept3 = Fixture::copy("sample/simple.ept");
    let out1 = Fixture::blank("out1.ept");
    let out2 = Fixture::blank("out2.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-e")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept1.path)
        .arg("-o")
        .arg(&out1.path)
        .arg(&ept2.path)
        .arg("-o")
        .arg(&out2.path)
        .arg(&ept3.path)
        .assert()
        .success();
    // these originals should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept1.source).unwrap(),
        &fs::read_to_string(&ept1.path).unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&ept2.source).unwrap(),
        &fs::read_to_string(&ept2.path).unwrap()
    );
    // these two have outputs specified
    assert_eq!(
        &fs::read_to_string(&out1.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&out2.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap()
    );
    // no output specified for this one, so the input is the output
    assert_eq!(
        &fs::read_to_string(&ept3.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap()
    );
}
