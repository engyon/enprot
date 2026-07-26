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

#[test]
fn resolve_per_word_override_wins_over_global_mode() {
    // TODO.roadmap/56: --word WORD:MODE overrides --mode for that
    // specific WORD.
    let dir = tempdir().unwrap();
    let ept = dir.path().join("file.ept");
    // Two conflicts: X (override to ours) and Y (fallback to theirs).
    fs::write(
        &ept,
        "// <( CONFLICT X )>\n// <( OURS )>\n// <( BEGIN X )>\nhi-our\n// <( END X )>\n// <( THEIRS )>\n// <( BEGIN X )>\nhi-their\n// <( END X )>\n// <( END X )>\n// <( CONFLICT Y )>\n// <( OURS )>\n// <( BEGIN Y )>\nyo-our\n// <( END Y )>\n// <( THEIRS )>\n// <( BEGIN Y )>\nyo-their\n// <( END Y )>\n// <( END Y )>\n",
    )
    .unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["resolve", "--mode", "theirs", "--word", "X:ours"])
        .arg(&ept)
        .assert()
        .success();

    let s = fs::read_to_string(&ept).unwrap();
    assert!(s.contains("hi-our"), "X override to ours: {s}");
    assert!(!s.contains("hi-their"), "no theirs for X: {s}");
    assert!(s.contains("yo-their"), "Y falls back to theirs: {s}");
    assert!(!s.contains("yo-our"), "no ours for Y: {s}");
}
