// Integration tests for `--format json` (TODO.roadmap/41).
//
// Each inspection subcommand (capabilities, list, verify-chain) emits a
// versioned JSON envelope when `--format json` is passed. Text remains
// the default. These tests assert the envelope shape and round-trip via
// serde_json::Value so they don't break on minor formatting changes.

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

fn schema_of(s: &str) -> String {
    let v: Value = serde_json::from_str(s).expect("output must be valid JSON");
    v.get("$schema")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default()
}

#[test]
fn capabilities_json_emits_envelope() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--format", "json"])
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert_eq!(schema_of(s), "enprot/v1");
    let v: Value = serde_json::from_str(s).unwrap();
    let caps = v
        .get("capabilities")
        .and_then(|v| v.as_array())
        .expect("capabilities array");
    assert!(
        caps.iter()
            .any(|c| { c.get("tier").and_then(|v| v.as_str()) == Some("viewer") })
    );
}

#[test]
fn capabilities_json_with_password_lists_decryptor() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["-k", "Agent_007=topsecret"])
        .args(["--format", "json"])
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    let v: Value = serde_json::from_str(s).unwrap();
    let caps = v
        .get("capabilities")
        .and_then(|v| v.as_array())
        .expect("capabilities array");
    let decryptors: Vec<&str> = caps
        .iter()
        .filter_map(|c| {
            if c.get("tier").and_then(|v| v.as_str()) == Some("decryptor") {
                c.get("word").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .collect();
    assert!(decryptors.contains(&"Agent_007"));
}

#[test]
fn capabilities_text_default_unchanged() {
    let dir = tempdir().unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .arg("capabilities")
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert!(!s.contains("$schema"), "text mode should not emit JSON");
    assert!(s.contains("viewer"));
}

#[test]
fn list_json_emits_envelope_with_nodes() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("input.ept");
    std::fs::write(
        &ept,
        "// <( BEGIN Agent_007 )>\nhello\n// <( END Agent_007 )>\n",
    )
    .unwrap();
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--format", "json", "list"])
        .arg(&ept)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert_eq!(schema_of(s), "enprot/v1");
    let v: Value = serde_json::from_str(s).unwrap();
    let files = v
        .get("files")
        .and_then(|v| v.as_array())
        .expect("files array");
    assert_eq!(files.len(), 1);
    let nodes = files[0].get("nodes").and_then(|v| v.as_array()).unwrap();
    assert!(nodes.iter().any(|n| {
        n.get("type").and_then(|v| v.as_str()) == Some("begin-end")
            && n.get("word").and_then(|v| v.as_str()) == Some("Agent_007")
    }));
}

#[test]
fn verify_chain_json_emits_envelope() {
    let dir = tempdir().unwrap();
    let ept = dir.path().join("input.ept");
    std::fs::write(&ept, "// <( BEGIN PUBLIC )>\nhi\n// <( END PUBLIC )>\n").unwrap();

    let out = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--format", "json", "verify-chain"])
        .arg(&ept)
        .assert()
        .success();
    let s = std::str::from_utf8(&out.get_output().stdout).unwrap();
    assert_eq!(schema_of(s), "enprot/v1");
    let v: Value = serde_json::from_str(s).unwrap();
    assert_eq!(v.get("ok").and_then(|v| v.as_bool()), Some(true));
    let files = v
        .get("files")
        .and_then(|v| v.as_array())
        .expect("files array");
    assert_eq!(files.len(), 1);
    assert_eq!(
        files[0].get("anchors_total").and_then(|v| v.as_u64()),
        Some(0)
    );
}
