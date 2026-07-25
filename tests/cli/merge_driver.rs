// Integration tests for the merge driver (TODO.roadmap/43).
//
// `enprot merge-driver %O %A %B %P` runs git's custom merge-driver
// contract: read three files, write the merged result back into the
// "ours" path (the second positional arg).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn read(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn merge_driver_disjoint_word_edits_merge_cleanly() {
    let dir = tempdir().unwrap();
    let base = dir.path().join("base.ept");
    let ours = dir.path().join("ours.ept");
    let theirs = dir.path().join("theirs.ept");

    write(
        &base,
        "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho\n// <( END GEHEIM )>\n",
    );
    write(
        &ours,
        "// <( BEGIN Agent_007 )>\nhi-our\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho\n// <( END GEHEIM )>\n",
    );
    write(
        &theirs,
        "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho-their\n// <( END GEHEIM )>\n",
    );

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("merge-driver")
        .arg(&base)
        .arg(&ours)
        .arg(&theirs)
        .assert()
        .success();

    let merged = read(&ours);
    assert!(merged.contains("hi-our"), "merged = {merged}");
    assert!(merged.contains("ho-their"), "merged = {merged}");
    assert!(
        !merged.contains("CONFLICT"),
        "no conflicts expected: {merged}"
    );
}

#[test]
fn merge_driver_same_word_different_content_emits_conflict() {
    let dir = tempdir().unwrap();
    let base = dir.path().join("base.ept");
    let ours = dir.path().join("ours.ept");
    let theirs = dir.path().join("theirs.ept");

    write(
        &base,
        "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n",
    );
    write(
        &ours,
        "// <( BEGIN Agent_007 )>\nhi-our\n// <( END Agent_007 )>\n",
    );
    write(
        &theirs,
        "// <( BEGIN Agent_007 )>\nhi-their\n// <( END Agent_007 )>\n",
    );

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("merge-driver")
        .arg(&base)
        .arg(&ours)
        .arg(&theirs)
        .assert()
        .success();

    let merged = read(&ours);
    assert!(merged.contains("CONFLICT Agent_007"), "merged = {merged}");
    assert!(merged.contains("OURS"), "merged = {merged}");
    assert!(merged.contains("THEIRS"), "merged = {merged}");
    assert!(merged.contains("hi-our"));
    assert!(merged.contains("hi-their"));
}

#[test]
fn merge_driver_identical_files_produce_no_conflicts() {
    let dir = tempdir().unwrap();
    let base = dir.path().join("base.ept");
    let ours = dir.path().join("ours.ept");
    let theirs = dir.path().join("theirs.ept");

    let body = "// <( BEGIN X )>\nbody\n// <( END X )>\n";
    write(&base, body);
    write(&ours, body);
    write(&theirs, body);

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("merge-driver")
        .arg(&base)
        .arg(&ours)
        .arg(&theirs)
        .assert()
        .success();

    assert_eq!(read(&ours), body);
}

#[test]
fn merge_driver_output_is_reparseable_ept() {
    // Critical invariant: even when conflicts are emitted, the file
    // must still parse — `enprot list` and `enprot verify` must work
    // on a working tree with unresolved conflicts. The user runs
    // `enprot resolve` to clear them.
    let dir = tempdir().unwrap();
    let base = dir.path().join("base.ept");
    let ours = dir.path().join("ours.ept");
    let theirs = dir.path().join("theirs.ept");

    write(&base, "// <( BEGIN X )>\nbody\n// <( END X )>\n");
    write(&ours, "// <( BEGIN X )>\nbody-our\n// <( END X )>\n");
    write(&theirs, "// <( BEGIN X )>\nbody-their\n// <( END X )>\n");

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("merge-driver")
        .arg(&base)
        .arg(&ours)
        .arg(&theirs)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("list")
        .arg(&ours)
        .assert()
        .success();
}
