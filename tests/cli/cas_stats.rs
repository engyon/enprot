use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn cas_stats_shows_blob_count_and_sizes() {
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
        .arg("stats")
        .assert()
        .success()
        .stderr(
            predicates::str::contains("Blobs:")
                .and(predicates::str::contains("Total:"))
                .and(predicates::str::contains("Smallest:"))
                .and(predicates::str::contains("Largest:"))
                .and(predicates::str::contains("Average:")),
        );
}

#[test]
fn cas_stats_empty_store() {
    let casdir = tempdir().unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("cas")
        .arg("stats")
        .assert()
        .success()
        .stderr(predicates::str::contains("Blobs:     0"));
}

#[test]
fn cas_stats_json_output() {
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
        .arg("stats")
        .assert()
        .success()
        .stdout(
            predicates::str::contains("\"$schema\": \"enprot/v1\"")
                .and(predicates::str::contains("\"blobs\": 2"))
                .and(predicates::str::contains("\"total_bytes\""))
                .and(predicates::str::contains("\"min_bytes\""))
                .and(predicates::str::contains("\"max_bytes\""))
                .and(predicates::str::contains("\"avg_bytes\"")),
        );
}
