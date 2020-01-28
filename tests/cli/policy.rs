use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;

use Fixture;

fn test_policy_err(policy: &str, args: &[&str], err: &str) {
    let ept = Fixture::copy("sample/simple.ept");
    // not allowed
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg(policy)
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .args(args)
        .assert()
        .failure()
        .stderr(predicates::str::contains(err));
    // same for decryption
    let out = Fixture::copy("sample/simple.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--defaults") // load the defaults, but don't enforce it
        .arg(policy)
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg(&out.path)
        .args(args)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg(policy)
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&out.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(err));
}

fn test_policy_ok(policy: &str, args: &[&str]) {
    let ept = Fixture::copy("sample/simple.ept");
    let out = Fixture::blank("out.ept");
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg(policy)
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .args(args)
        .arg(&ept.path)
        .arg("-o")
        .arg(&out.path)
        .assert()
        .success();
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap()
    );
    // decryption
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg(policy)
        .arg("-d")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&out.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap()
    );
}

#[test]
fn nist_disallowed_pbkdfs() {
    test_policy_err(
        "nist",
        &["--pbkdf", "legacy"],
        "PBKDF algorithm is not permitted by policy",
    );
    test_policy_err(
        "nist",
        &["--pbkdf", "argon2"],
        "PBKDF algorithm is not permitted by policy",
    );
}

#[test]
fn nist_allowed_pbkdfs() {
    test_policy_ok("nist", &["--pbkdf", "pbkdf2-sha256"]);
    test_policy_ok("nist", &["--pbkdf", "pbkdf2-sha512"]);
}

#[test]
fn nist_pbkdf2_params() {
    // pbkdf2 requires a minimum iteration count
    test_policy_err(
        "nist",
        &["--pbkdf", "pbkdf2-sha256", "--pbkdf-params", "i=999"],
        "Iteration count violates policy",
    );
    test_policy_err(
        "nist",
        &["--pbkdf", "pbkdf2-sha512", "--pbkdf-params", "i=999"],
        "Iteration count violates policy",
    );

    test_policy_ok(
        "nist",
        &["--pbkdf", "pbkdf2-sha256", "--pbkdf-params", "i=1000"],
    );
    test_policy_ok(
        "nist",
        &["--pbkdf", "pbkdf2-sha512", "--pbkdf-params", "i=1000"],
    );
}

#[test]
fn nist_cipher() {
    test_policy_ok("nist", &["--cipher", "aes-256-gcm"]);

    test_policy_err(
        "nist",
        &[
            "--cipher",
            "aes-256-gcm",
            "--cipher-iv",
            "01020304050607080910111213141516",
        ],
        "IV length does not match NIST recommendations for this cipher",
    );
    test_policy_ok(
        "nist",
        &[
            "--cipher",
            "aes-256-gcm",
            "--cipher-iv",
            "010203040506070809101112",
        ],
    );

    // aes-256-siv is not allowed
    test_policy_err(
        "nist",
        &["--cipher", "aes-256-siv"],
        "Cipher algorithm is not permitted by policy",
    );

    // aes-256-gcm-siv is not allowed
    test_policy_err(
        "nist",
        &["--cipher", "aes-256-gcm-siv"],
        "Cipher algorithm is not permitted by policy",
    );
}

#[test]
fn fips_flag() {
    let ept = Fixture::copy("sample/simple.ept");

    // ensure we select some sane defaults
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--fips")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .success()
        .stdout(
            predicates::str::contains("pbkdf:$pbkdf2-sha512$")
                .and(predicates::str::contains("cipher:aes-256-gcm$iv=")),
        );

    // should not be able to set a conflicting policy
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--fips")
        .arg("--policy")
        .arg("default")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Policy setting of 'default' conflicts with --fips",
        ));
}

#[test]
fn defaults_policy_conflict() {
    let ept = Fixture::copy("sample/simple.ept");

    // nist policy conflicts with default settings
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("--policy")
        .arg("nist")
        .arg("--defaults")
        .arg("default")
        .arg("-e")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .arg("-o")
        .arg("-")
        .assert()
        .failure()
        .stderr(predicates::str::contains("not permitted by policy"));
}
