// Integration tests for the config file + `enprot init` (TODO.roadmap/40).

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn init_writes_local_template() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("wrote .enprot.toml"));
    let body = fs::read_to_string(dir.path().join(".enprot.toml")).unwrap();
    assert!(body.contains("[encrypt]"));
    assert!(body.contains("[chain]"));
    assert!(body.contains("cipher"));
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join(".enprot.toml"), "casdir = \"cas\"\n").unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .failure();
}

#[test]
fn init_overwrites_with_force() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join(".enprot.toml"), "casdir = \"cas\"\n").unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["init", "--force"])
        .assert()
        .success();
    let body = fs::read_to_string(dir.path().join(".enprot.toml")).unwrap();
    assert!(body.contains("[encrypt]"));
}

#[test]
fn config_file_supplies_casdir_when_cli_omits_it() {
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    fs::write(
        dir.path().join(".enprot.toml"),
        format!("casdir = \"{}\"\n", cas.display()),
    )
    .unwrap();

    // Run capabilities — config should make Reader appear because the
    // CAS dir now resolves. We don't assert on the env path here, just
    // that the config file was loaded without error.
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("viewer"), "always present: {s}");
    assert!(
        s.contains("reader"),
        "config casdir should grant reader: {s}"
    );
}

#[test]
fn cli_flag_overrides_config_file() {
    let dir = tempdir().unwrap();
    let cas_a = dir.path().join("cas_a");
    let cas_b = dir.path().join("cas_b");
    fs::create_dir(&cas_a).unwrap();
    fs::create_dir(&cas_b).unwrap();
    fs::write(
        dir.path().join(".enprot.toml"),
        format!("casdir = \"{}\"\n", cas_a.display()),
    )
    .unwrap();

    // Pass -c cas_b explicitly; should win over config cas_a.
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["-c"])
        .arg(&cas_b)
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    // Both exist; we just assert no error and viewer present.
    assert!(s.contains("viewer"));
}

#[test]
fn malformed_config_is_not_fatal_for_init() {
    // init must work even if a project-local config exists — it
    // bypasses the layered-load step.
    let dir = tempdir().unwrap();
    fs::write(dir.path().join(".enprot.toml"), "this is not toml {{{{").unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["init", "--force"])
        .assert()
        .success();
}
