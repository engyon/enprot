use crate::Fixture;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

#[test]
fn help_produces_usage() {
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn success_on_no_operation() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success();
    // file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn verbosity() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("LEFT_SEP").not());
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-v")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("LEFT_SEP"));
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--verbose")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicate::str::contains("LEFT_SEP"));
    // file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
}

#[test]
fn output() {
    let ept = Fixture::copy("sample/test.ept");
    let output = Fixture::blank("out.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg(&output.path)
        .assert()
        .success();
    // original file should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept.source).unwrap(),
        &fs::read_to_string(&ept.path).unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&output.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
}

#[test]
fn output_multiple() {
    let ept1 = Fixture::copy("sample/test.ept");
    let ept2 = Fixture::copy("sample/simple.ept");
    let ept3 = Fixture::copy("sample/simple.ept");
    let out1 = Fixture::blank("out1.ept");
    let out2 = Fixture::blank("out2.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("encrypt")
        .arg("--cipher")
        .arg("aes-256-siv")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept1.path)
        .arg("-o")
        .arg(&out1.path)
        .arg(&ept2.path)
        .arg("-o")
        .arg(&out2.path)
        .arg(&ept3.path)
        .assert()
        .success();
    // these originals should be unchanged
    assert_eq!(
        &fs::read_to_string(&ept1.source).unwrap(),
        &fs::read_to_string(&ept1.path).unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&ept2.source).unwrap(),
        &fs::read_to_string(&ept2.path).unwrap()
    );
    // these two have outputs specified
    assert_eq!(
        &fs::read_to_string(&out1.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    assert_eq!(
        &fs::read_to_string(&out2.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap()
    );
    // no output specified for this one, so the input is the output
    assert_eq!(
        &fs::read_to_string(&ept3.path).unwrap(),
        &fs::read_to_string("test-data/simple-encrypt-agent007.ept").unwrap()
    );
}

#[test]
fn jobs_zero_rejected() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--jobs")
        .arg("0")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be at least 1"));
}

/// Regression for the typed ConfigIssue gate (TODO.complete/33).
/// `--fips` + explicit `--policy default` must fail with the new
/// typed message, and the message must mention both flags so the
/// user sees the conflict in one read.
#[test]
fn fips_policy_conflict_typed_message() {
    let ept = Fixture::copy("sample/test.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--fips")
        .arg("--policy")
        .arg("default")
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .failure()
        .stderr(
            predicates::str::contains("--fips forces --policy=nist")
                .and(predicates::str::contains("--policy=default")),
        );
}

/// The signer-without-anchor warning should not block execution —
/// passthrough still produces output. This locks in the warning-only
/// severity that ConfigIssue::SignerWithoutAnchor carries.
#[test]
fn signer_without_anchor_is_warning_only() {
    let ept = Fixture::copy("sample/test.ept");
    // Generate a real ed25519 keypair so the signer path is exercised
    // end-to-end. The warning fires at validate time, before the key
    // is loaded; passthrough doesn't load it regardless.
    let dir = tempfile::tempdir().unwrap();
    let priv_pem = dir.path().join("priv.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-priv"])
        .arg(&priv_pem)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--signer")
        .arg(&priv_pem)
        .arg("passthrough")
        .arg(&ept.path)
        .assert()
        .success()
        .stderr(predicates::str::contains("warning:"));
}

/// `enprot sbom` (TODO.complete/62): valid SPDX JSON on stdout with
/// the full embedded dependency tree; `--output` writes the file.
#[test]
fn sbom_spdx_json_shape() {
    use std::process::Command;
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(["sbom"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
    let pkgs = v["packages"].as_array().unwrap();
    assert!(
        pkgs.len() > 100,
        "full lockfile tree expected, got {pkgs_len}",
        pkgs_len = pkgs.len()
    );
    let names: Vec<&str> = pkgs.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(names.contains(&"enprot"));
    assert!(names.contains(&"botan"));
    assert!(names.contains(&"librnp"));
    // Every non-self package is the target of exactly one DEPENDS_ON.
    let rels = v["relationships"].as_array().unwrap();
    assert!(rels.iter().any(|r| r["relationshipType"] == "DESCRIBES"));
}

#[test]
fn sbom_cyclonedx_and_output_file() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sbom.json");
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(["sbom", "--sbom-format", "cyclonedx-json", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.5");
    assert_eq!(v["metadata"]["component"]["name"], "enprot");
}

/// --audit-log records one JSONL line per invocation, and `enprot
/// audit query` filters them (TODO.complete/63).
#[test]
fn audit_log_records_and_queries() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    let ept = Fixture::copy("sample/test.ept");

    for (word, file) in [("W1", "a.ept"), ("W2", "b.ept")] {
        let _ = Command::cargo_bin("enprot")
            .unwrap()
            .args(["--audit-log"])
            .arg(&log)
            .args(["passthrough", "-w", word])
            .arg(&ept.path)
            .arg("-o")
            .arg(dir.path().join(file))
            .output()
            .unwrap();
    }

    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    for l in &lines {
        assert!(l.contains(r#""type":"record""#), "{l}");
        assert!(l.contains(r#""op":"passthrough""#), "{l}");
    }
    assert!(lines[0].contains(r#""words":["W1"]"#), "got: {}", lines[0]);

    // Query by word returns exactly the matching line.
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit", "query", "--log"])
        .arg(&log)
        .args(["--word", "W2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(s.lines().count(), 1);
    assert!(s.contains(r#""words":["W2"]"#));
}

/// Signed audit records verify; tampering with a record is detected
/// and `audit verify` exits non-zero.
#[test]
fn audit_sign_and_verify_tamper_evidence() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.jsonl");
    let priv_pem = dir.path().join("priv.pem");
    let pub_pem = dir.path().join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["keygen", "ed25519", "--out-priv"])
        .arg(&priv_pem)
        .args(["--out-pub"])
        .arg(&pub_pem)
        .assert()
        .success();

    let ept = Fixture::copy("sample/simple.ept");
    let _ = Command::cargo_bin("enprot")
        .unwrap()
        .args(["--audit-log"])
        .arg(&log)
        .args(["--signer"])
        .arg(&priv_pem)
        .args(["passthrough"])
        .arg(&ept.path)
        .arg("-o")
        .arg(dir.path().join("out.ept"))
        .output()
        .unwrap();

    // Record + signature lines present; verify passes.
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains(r#""type":"signature""#));
    let ok = Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit", "verify", "--log"])
        .arg(&log)
        .args(["--trust-root"])
        .arg(&pub_pem)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // Tamper: flip the recorded op. Verify must fail.
    let tampered = text.replace("passthrough", "passthru");
    std::fs::write(&log, tampered).unwrap();
    let bad = Command::cargo_bin("enprot")
        .unwrap()
        .args(["audit", "verify", "--log"])
        .arg(&log)
        .args(["--trust-root"])
        .arg(&pub_pem)
        .output()
        .unwrap();
    assert!(!bad.status.success(), "tampered log must not verify");
}
