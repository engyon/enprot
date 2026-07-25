// Integration tests for `enprot resolve` (TODO.roadmap/44).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

const CONFLICT_FILE: &str = "// <( CONFLICT Agent_007 )>
// <( OURS )>
// <( BEGIN Agent_007 )>
hi-our
// <( END Agent_007 )>
// <( THEIRS )>
// <( BEGIN Agent_007 )>
hi-their
// <( END Agent_007 )>
// <( END Agent_007 )>
";

#[test]
fn resolve_ours_clears_conflict() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "ours"])
        .arg(&ept)
        .assert()
        .success();

    let s = fs::read_to_string(&ept).unwrap();
    assert!(!s.contains("CONFLICT"), "got: {s}");
    assert!(s.contains("hi-our"));
    assert!(!s.contains("hi-their"));
}

#[test]
fn resolve_theirs_clears_conflict() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "theirs"])
        .arg(&ept)
        .assert()
        .success();

    let s = fs::read_to_string(&ept).unwrap();
    assert!(!s.contains("CONFLICT"));
    assert!(s.contains("hi-their"));
    assert!(!s.contains("hi-our"));
}

#[test]
fn resolve_both_keeps_both_sides() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "both"])
        .arg(&ept)
        .assert()
        .success();

    let s = fs::read_to_string(&ept).unwrap();
    assert!(!s.contains("CONFLICT"));
    assert!(s.contains("hi-our"));
    assert!(s.contains("hi-their"));
}

#[test]
fn resolve_skip_drops_both_sides() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "skip"])
        .arg(&ept)
        .assert()
        .success();

    let s = fs::read_to_string(&ept).unwrap();
    assert!(!s.contains("CONFLICT"));
    assert!(!s.contains("hi-our"));
    assert!(!s.contains("hi-their"));
}

#[test]
fn resolve_on_clean_file_is_noop() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    let body = "// <( BEGIN X )>\nbody\n// <( END X )>\n";
    fs::write(&ept, body).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "ours"])
        .arg(&ept)
        .assert()
        .success();

    assert_eq!(fs::read_to_string(&ept).unwrap(), body);
}

#[test]
fn resolve_interactive_without_tty_fails_cleanly() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    // assert_cmd runs with stdin not connected to a TTY; the
    // interactive mode should refuse rather than hang.
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve"]) // default mode = interactive
        .arg(&ept)
        .assert()
        .failure();
}

#[test]
fn resolved_file_is_reparseable_ept() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "ours"])
        .arg(&ept)
        .assert()
        .success();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("list")
        .arg(&ept)
        .assert()
        .success();
}
