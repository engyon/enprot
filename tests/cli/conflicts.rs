// Integration tests for `enprot conflicts` (TODO.roadmap/49).

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
fn conflicts_lists_unresolved_blocks() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("f.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["conflicts"])
        .arg(&ept)
        .assert()
        .failure();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("Agent_007"), "got: {s}");
}

#[test]
fn conflicts_clean_file_exits_zero() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("f.ept");
    fs::write(&ept, "// <( BEGIN X )>\nbody\n// <( END X )>\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["conflicts"])
        .arg(&ept)
        .assert()
        .success();
}

#[test]
fn conflicts_json_emits_envelope() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("f.ept");
    fs::write(&ept, CONFLICT_FILE).unwrap();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--format", "json", "conflicts"])
        .arg(&ept)
        .assert()
        .failure();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("$schema"), "got: {s}");
    assert!(s.contains("Agent_007"));
}
