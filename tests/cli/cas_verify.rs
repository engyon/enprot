use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

/// Helper: run `enprot store` to populate CAS from the sample fixture,
/// returning the casdir and the stored output path.
struct StoredFixture {
    casdir: tempfile::TempDir,
    ept: Fixture,
}

fn store_sample(word: &str) -> StoredFixture {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("store")
        .arg("-w")
        .arg(word)
        .arg(&ept.path)
        .assert()
        .success();
    StoredFixture { casdir, ept }
}

// Known hashes from storing Agent_007 from sample/test.ept.
const HASH_BOND: &str = "d094e230861eb0ab43b895b8ecdeeb9e3a7e4a88239341a81da832ac181feaab";
const HASH_SECRET: &str = "575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306";

#[test]
fn cas_verify_all_ok() {
    let s = store_sample("Agent_007");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("verify")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stderr(
            predicates::str::contains("OK")
                .and(predicates::str::contains(HASH_BOND))
                .and(predicates::str::contains(HASH_SECRET))
                .and(predicates::str::contains("2 OK, 0 FAIL")),
        );
}

#[test]
fn cas_verify_missing_blob() {
    let s = store_sample("Agent_007");
    // Delete one blob from CAS.
    fs::remove_file(s.casdir.path().join(HASH_BOND)).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("verify")
        .arg(&s.ept.path)
        .assert()
        .failure()
        .stderr(
            predicates::str::contains("FAIL")
                .and(predicates::str::contains(HASH_BOND))
                .and(predicates::str::contains("1 OK, 1 FAIL")),
        );
}

#[test]
fn cas_verify_corrupt_blob() {
    let s = store_sample("Agent_007");
    // Overwrite a blob with content that doesn't match its hash.
    fs::write(
        s.casdir.path().join(HASH_BOND),
        b"this is definitely not James Bond\n",
    )
    .unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("verify")
        .arg(&s.ept.path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("FAIL").and(predicates::str::contains(HASH_BOND)));
}

#[test]
fn cas_verify_no_cas_references() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    // No store/fetch — the file has BEGIN/END but no STORED/INCLUDE.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("cas")
        .arg("verify")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("no CAS references found"));
}

#[test]
fn cas_verify_json_output() {
    let s = store_sample("Agent_007");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("--format")
        .arg("json")
        .arg("cas")
        .arg("verify")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stdout(
            predicates::str::contains("\"$schema\": \"enprot/v1\"")
                .and(predicates::str::contains("\"checked\": 2"))
                .and(predicates::str::contains("\"ok\": 2"))
                .and(predicates::str::contains("\"fail\": 0"))
                .and(predicates::str::contains(HASH_BOND))
                .and(predicates::str::contains("\"status\": \"ok\"")),
        );
}

#[test]
fn cas_verify_deduplicates() {
    // sample/test.ept has Agent_007 referenced twice; storing produces
    // two STORED lines with different hashes (different content). But
    // if the same hash appeared twice, we should check it only once.
    // This test verifies the dedup path: create a file with two
    // identical STORED references and confirm only 1 hash is checked.
    let casdir = tempdir().unwrap();
    let ept = Fixture::blank("dup.ept");
    fs::write(
        &ept.path,
        format!("// <( STORED word {HASH_BOND} )>\n// <( STORED word {HASH_BOND} )>\n"),
    )
    .unwrap();
    // Put the blob in CAS.
    fs::write(casdir.path().join(HASH_BOND), b"James Bond\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("cas")
        .arg("verify")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("1 OK, 0 FAIL (1 unique"));
}
