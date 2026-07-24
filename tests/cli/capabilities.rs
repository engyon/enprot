use assert_cmd::Command;
use tempfile::tempdir;

// PQC Phase 1 + capability model integration: `enprot capabilities`
// surfaces what the current flag set unlocks. This is the foundation
// for the merge driver and policy enforcement (TODO.finalize/14).
//
// Note: the implicit casdir default (`.` if no `cas/` dir exists) means
// Reader is present in any working directory. Tests below assert the
// tier is granted; tighter "Reader only when CAS is explicit" semantics
// would be a behavior change for existing callers and is out of scope.

#[test]
fn capabilities_with_no_flags_shows_viewer_baseline() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("viewer"));
}

#[test]
fn capabilities_with_passwords_shows_decryptor_per_word() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["-k", "Agent_007=password"])
        .args(["-k", "GEHEIM=secret"])
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("decryptor(Agent_007)"));
    assert!(s.contains("decryptor(GEHEIM)"));
    assert!(s.contains("viewer"));
}

#[test]
fn capabilities_with_explicit_casdir_shows_reader() {
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    std::fs::create_dir(&cas).unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["-c"])
        .arg(&cas)
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(s.contains("reader"));
    assert!(s.contains("viewer"));
}
