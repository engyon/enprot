// Integration tests for `enprot inspect` (TODO.finalize/42).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write(path: &std::path::Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn write_lines(path: &std::path::Path, lines: &[&str]) {
    write(path, &lines.join("\n"))
}

#[test]
fn inspect_shows_begin_end_segments() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("a.ept");
    write(
        &input,
        "hello\n// <( BEGIN Secret )>\nhidden line\n// <( END Secret )>\n",
    );

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["inspect"])
        .arg(&input)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("structure"), "missing structure section: {s}");
    assert!(s.contains("Secret"), "WORD should appear: {s}");
    assert!(s.contains("chain anchors"), "missing chain section: {s}");
    assert!(s.contains("conflicts"), "missing conflict section: {s}");
    assert!(
        s.contains("capabilities"),
        "missing capability section: {s}"
    );
}

#[test]
fn inspect_reports_no_conflicts_when_clean() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("a.ept");
    write(&input, "plain text only\n");

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["inspect"])
        .arg(&input)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("(none)"), "should show no conflicts: {s}");
}

#[test]
fn inspect_exits_nonzero_when_conflicts_present() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("conflict.ept");
    write_lines(
        &input,
        &[
            "// <( CONFLICT Secret )>",
            "// <( OURS )>",
            "our content",
            "// <( THEIRS )>",
            "their content",
            "// <( END Secret )>",
        ],
    );

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["inspect"])
        .arg(&input)
        .assert()
        .failure();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(
        s.contains("1 unresolved conflict"),
        "should count conflict: {s}"
    );
}

#[test]
fn inspect_shows_encrypted_block_metadata() {
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let input = dir.path().join("a.ept");
    write_lines(
        &input,
        &[
            "// <( ENCRYPTED Secret cipher:$aes-256-siv$iv=MDEyMzQ1Njc4OWFiY2RlZg== )>",
            "// <( DATA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA )>",
            "// <( END Secret )>",
        ],
    );

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["inspect"])
        .arg(&input)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("ENCRYPTED"), "should show ENCRYPTED kind: {s}");
    assert!(s.contains("Secret"), "WORD should appear: {s}");
}
