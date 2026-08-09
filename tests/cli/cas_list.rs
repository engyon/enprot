use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::tempdir;

const HASH_BOND: &str = "d094e230861eb0ab43b895b8ecdeeb9e3a7e4a88239341a81da832ac181feaab";
const HASH_SECRET: &str = "575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306";

#[test]
fn cas_list_shows_all_blobs() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("store")
        .arg("-w")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("cas")
        .arg("list")
        .assert()
        .success()
        .stdout(predicates::str::contains(HASH_BOND).and(predicates::str::contains(HASH_SECRET)))
        .stderr(predicates::str::contains("2 blobs"));
}

#[test]
fn cas_list_empty_store() {
    let casdir = tempdir().unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("cas")
        .arg("list")
        .assert()
        .success()
        .stderr(predicates::str::contains("0 blobs"));
}

#[test]
fn cas_list_json_output() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("store")
        .arg("-w")
        .arg("Agent_007")
        .arg(&ept.path)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--format")
        .arg("json")
        .arg("cas")
        .arg("list")
        .assert()
        .success()
        .stdout(
            predicates::str::contains("\"$schema\": \"enprot/v1\"")
                .and(predicates::str::contains("\"count\": 2"))
                .and(predicates::str::contains(HASH_BOND)),
        );
}
