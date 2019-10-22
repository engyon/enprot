extern crate assert_cmd;
extern crate predicates;

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use Fixture;

#[test]
fn store_fetch_single() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-s")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306")
        )
        .unwrap(),
        "Super secret line 3\n"
    );
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("d094e230861eb0ab43b895b8ecdeeb9e3a7e4a88239341a81da832ac181feaab")
        )
        .unwrap(),
        "James Bond\n"
    );
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-store-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-f")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn store_fetch_both_single_arg() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--casdir")
        .arg(casdir.path())
        .arg("--store")
        .arg("Agent_007,GEHEIM")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306")
        )
        .unwrap(),
        "Super secret line 3\n"
    );
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("cea67c3ef34ff899793b557e9178c1b97bbcfe9722df2f6d35d2d0c91d2c1fe4")
        )
        .unwrap(),
        "Secret line 1
Secret line 2
// <( BEGIN Agent_007 )>
James Bond
// <( END Agent_007 )>\n"
    );
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-store-both.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--casdir")
        .arg(casdir.path())
        .arg("--fetch")
        .arg("Agent_007,GEHEIM")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn store_fetch_both_multiple_args() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-s")
        .arg("Agent_007")
        .arg("-s")
        .arg("GEHEIM")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306")
        )
        .unwrap(),
        "Super secret line 3\n"
    );
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("cea67c3ef34ff899793b557e9178c1b97bbcfe9722df2f6d35d2d0c91d2c1fe4")
        )
        .unwrap(),
        "Secret line 1
Secret line 2
// <( BEGIN Agent_007 )>
James Bond
// <( END Agent_007 )>\n"
    );
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-store-both.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-f")
        .arg("Agent_007,GEHEIM")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn store_fetch_alt_sep() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test-alt-sep.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-l")
        .arg("{")
        .arg("-r")
        .arg("}")
        .arg("-s")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306")
        )
        .unwrap(),
        "Super secret line 3\n"
    );
    assert_eq!(
        &fs::read_to_string(
            casdir
                .path()
                .join("d094e230861eb0ab43b895b8ecdeeb9e3a7e4a88239341a81da832ac181feaab")
        )
        .unwrap(),
        "James Bond\n"
    );
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-alt-sep-store-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-l")
        .arg("{")
        .arg("-r")
        .arg("}")
        .arg("-f")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}
