//! Snapshot tests (TODO.complete/44) for stable, machine-produced
//! CLI output. Snapshots live in `tests/snapshots/` and are
//! committed; an output change produces a `.snap.new` file and a
//! failing test — review with `cargo insta review`, accept with
//! `cargo insta accept` (or `INSTA_UPDATE=always cargo test`).
//!
//! Selection rule (see the TODO): snapshot output that is long,
//! structured, and machine-produced; keep `assert_eq!` for short
//! hand-written expectations; never snapshot unstable output (random
//! IVs, timestamps, environment-dependent versions). Paths embedded
//! in output are normalized (tempdirs) and CRLF is folded so the
//! same snapshot passes on every platform.

use crate::Fixture;
use assert_cmd::prelude::*;
use std::process::Command;

/// Run enprot with args and return stdout with CRLF folded to LF.
fn run(args: &[&str]) -> String {
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
}

/// Like `run`, but with a fixture copied into a tempdir; the
/// tempdir path is normalized out of the output so the snapshot is
/// machine-independent. Both the raw path and its JSON-escaped form
/// (backslashes doubled) are replaced — JSON output on Windows embeds
/// the escaped variant, which a plain replace would miss.
fn run_with_fixture(args: &[&str], fixture: &str) -> String {
    let f = Fixture::copy(fixture);
    let path = f.path.display().to_string();
    let owned: Vec<String> = args.iter().map(|a| a.replace("{FILE}", &path)).collect();
    let argv: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
    run(&argv)
        .replace(&path, "<FIXTURE>")
        .replace(&path.replace('\\', "\\\\"), "<FIXTURE>")
}

#[test]
fn inspect_text() {
    let out = run_with_fixture(
        &["inspect", "--format", "text", "{FILE}"],
        "sample/test.ept",
    );
    insta::assert_snapshot!(out);
}

#[test]
fn inspect_json() {
    let out = run_with_fixture(
        &["inspect", "--format", "json", "{FILE}"],
        "sample/test.ept",
    );
    insta::assert_snapshot!(out);
}

#[test]
fn list_json() {
    let out = run_with_fixture(&["list", "--format", "json", "{FILE}"], "sample/test.ept");
    insta::assert_snapshot!(out);
}

#[test]
fn capabilities_text() {
    // No CAS dir in the tempdir → the implied capability set is the
    // stable baseline (Viewer only).
    let out = run(&["capabilities"]);
    insta::assert_snapshot!(out);
}

#[test]
fn cas_stats_json_empty_store() {
    // An empty CAS store: stable, structure-complete JSON envelope.
    let dir = tempfile::tempdir().unwrap();
    let cas = dir.path().display().to_string();
    let out = run(&["cas", "stats", "--format", "json", "-c", &cas]);
    insta::assert_snapshot!(out);
}
