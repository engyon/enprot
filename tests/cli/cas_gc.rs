use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

/// Helper: store Agent_007 from the sample fixture, returning the
/// casdir (with 2 blobs) and the stored EPT path.
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

/// Write a fake orphan blob (content doesn't need to match the hash
/// for GC — GC only checks whether the hash is referenced, not whether
/// the content is valid).
fn write_orphan(casdir: &std::path::Path, hash: &str, content: &[u8]) {
    fs::write(casdir.join(hash), content).unwrap();
}

const ORPHAN_HASH_A: &str = "aaaa1100000000000000000000000000000000000000000000000000000000aa";
const ORPHAN_HASH_B: &str = "bbbb2200000000000000000000000000000000000000000000000000000000bb";

#[test]
fn cas_gc_keeps_referenced_blobs() {
    let s = store_sample("Agent_007");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("gc")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("0 deleted").or(predicates::str::contains("deleted 0")));

    // Both blobs should still exist.
    assert!(s.casdir.path().join(HASH_BOND).exists());
    assert!(s.casdir.path().join(HASH_SECRET).exists());
}

#[test]
fn cas_gc_deletes_orphans() {
    let s = store_sample("Agent_007");
    write_orphan(s.casdir.path(), ORPHAN_HASH_A, b"orphan content a");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("gc")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("1 deleted").or(predicates::str::contains("deleted 1")));

    // Referenced blobs survive; orphan is gone.
    assert!(s.casdir.path().join(HASH_BOND).exists());
    assert!(s.casdir.path().join(HASH_SECRET).exists());
    assert!(!s.casdir.path().join(ORPHAN_HASH_A).exists());
}

#[test]
fn cas_gc_dry_run_preserves_everything() {
    let s = store_sample("Agent_007");
    write_orphan(s.casdir.path(), ORPHAN_HASH_A, b"orphan content a");
    write_orphan(s.casdir.path(), ORPHAN_HASH_B, b"orphan content b");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--dry-run")
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("gc")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("would delete 2"));

    // Dry-run: nothing actually deleted.
    assert!(s.casdir.path().join(ORPHAN_HASH_A).exists());
    assert!(s.casdir.path().join(ORPHAN_HASH_B).exists());
}

#[test]
fn cas_gc_min_age_protests_young_blobs() {
    let s = store_sample("Agent_007");
    write_orphan(s.casdir.path(), ORPHAN_HASH_A, b"orphan content a");

    // --min-age 3600: the orphan was just created, so it's protected.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("gc")
        .arg("--min-age")
        .arg("3600")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("0 deleted").or(predicates::str::contains("deleted 0")));

    // Orphan survives because it's too young.
    assert!(s.casdir.path().join(ORPHAN_HASH_A).exists());
}

#[test]
fn cas_gc_json_output() {
    let s = store_sample("Agent_007");
    write_orphan(s.casdir.path(), ORPHAN_HASH_A, b"orphan content a");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("--format")
        .arg("json")
        .arg("cas")
        .arg("gc")
        .arg(&s.ept.path)
        .assert()
        .success()
        .stdout(
            predicates::str::contains("\"$schema\": \"enprot/v1\"")
                .and(predicates::str::contains("\"total\": 3"))
                .and(predicates::str::contains("\"kept\": 2"))
                .and(predicates::str::contains("\"deleted\": 1"))
                .and(predicates::str::contains(ORPHAN_HASH_A))
                .and(predicates::str::contains("\"dry_run\": false")),
        );
}

#[test]
fn cas_gc_ignores_non_blob_files() {
    let s = store_sample("Agent_007");
    // Write a file with a non-hex name — should be ignored by GC.
    fs::write(s.casdir.path().join("README.txt"), b"not a blob").unwrap();
    // Write a file with uppercase hex — also not a valid CAS blob name.
    fs::write(
        s.casdir
            .path()
            .join("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"),
        b"uppercase",
    )
    .unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(s.casdir.path())
        .arg("cas")
        .arg("gc")
        .arg(&s.ept.path)
        .assert()
        .success();

    // Non-blob files survive.
    assert!(s.casdir.path().join("README.txt").exists());
}
