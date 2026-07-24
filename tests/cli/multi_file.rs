use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

// Issue #18: `-p output/` (trailing slash) should place outputs inside
// the directory with their original basename. Previously it produced
// `output/file.ept` only by accident when input was `file.ept` (no
// directory components); it broke for `inputdir/file.ept`.
#[test]
fn prefix_trailing_slash_uses_basename() {
    let in_dir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let src = in_dir.path().join("test.ept");
    fs::write(
        &src,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();

    // -p with a trailing slash should treat the prefix as a directory.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg("-p")
        .arg(format!("{}/", out_dir.path().display()))
        .arg(&src)
        .assert()
        .success();

    let expected_out = out_dir.path().join("test.ept");
    assert!(
        expected_out.is_file(),
        "expected output at {}",
        expected_out.display()
    );
}

#[test]
fn prefix_existing_dir_uses_basename() {
    let in_dir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let src = in_dir.path().join("test.ept");
    fs::write(
        &src,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();

    // -p with an existing directory (no trailing slash) — same behavior.
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg("-p")
        .arg(out_dir.path())
        .arg(&src)
        .assert()
        .success();

    let expected_out = out_dir.path().join("test.ept");
    assert!(
        expected_out.is_file(),
        "expected output at {}",
        expected_out.display()
    );
}

// The legacy "prepend verbatim" mode of `-p` is preserved (no trailing
// slash, prefix doesn't exist as a directory), but it's awkward to test
// in isolation because prepending to an absolute path produces an
// invalid path. Covered implicitly by tests/cli/misc.rs::output_multiple
// which uses `-o` pairing instead.

#[test]
fn output_dir_flag_places_files_in_directory() {
    let in_dir = tempdir().unwrap();
    let out_dir = tempdir().unwrap();
    let src1 = in_dir.path().join("a.ept");
    let src2 = in_dir.path().join("b.ept");
    fs::write(
        &src1,
        "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    fs::write(
        &src2,
        "// <( BEGIN Agent_007 )>\nho\n// <( END Agent_007 )>\n",
    )
    .unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg("--output-dir")
        .arg(out_dir.path())
        .arg(&src1)
        .arg(&src2)
        .assert()
        .success();

    assert!(out_dir.path().join("a.ept").is_file());
    assert!(out_dir.path().join("b.ept").is_file());
}

#[test]
fn output_dir_conflicts_with_prefix() {
    let out_dir = tempdir().unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg("--output-dir")
        .arg(out_dir.path())
        .arg("-p")
        .arg("some-prefix-")
        .arg("-")
        .assert()
        .failure();
}
