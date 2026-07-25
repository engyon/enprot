// Integration tests for capability policy (TODO.roadmap/46).

use crate::Fixture;
use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write_pubkey(dir: &tempfile::TempDir) -> String {
    // Generate an Ed25519 keypair and write out the pubkey PEM. The
    // fingerprint is then computed and embedded in the policy.
    let priv_path = dir.path().join("priv.pem");
    let pub_path = dir.path().join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["keygen", "ed25519"])
        .args(["--out-priv", priv_path.to_str().unwrap()])
        .args(["--out-pub", pub_path.to_str().unwrap()])
        .assert()
        .success();
    pub_path.to_str().unwrap().to_string()
}

fn fingerprint_hex(pub_pem_path: &str) -> String {
    let out = Command::cargo_bin("enprot")
        .unwrap()
        .arg("fingerprint")
        .arg(pub_pem_path)
        .assert()
        .success();
    std::str::from_utf8(&out.get_output().stdout)
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn verify_chain_with_policy_accepts_listed_signer() {
    let dir = tempdir().unwrap();
    let pub_path = write_pubkey(&dir);
    let fp = fingerprint_hex(&pub_path);
    let policy_path = dir.path().join("policy.toml");
    fs::write(
        &policy_path,
        format!(
            "[chain]\ntrust_roots = [\"ed25519:{fp}\"]\nrequire_monotonic_timestamps = false\n"
        ),
    )
    .unwrap();

    // Make a simple EPT file with no anchors — trivially passes.
    let ept = dir.path().join("input.ept");
    fs::write(&ept, "// <( BEGIN PUBLIC )>\nhi\n// <( END PUBLIC )>\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--policy-file", policy_path.to_str().unwrap()])
        .args(["verify-chain"])
        .arg(&ept)
        .assert()
        .success();
}

#[test]
fn verify_chain_with_policy_rejects_unlisted_signer() {
    let dir = tempdir().unwrap();
    // Trust only a fake fp that won't match anything we sign with.
    let policy_path = dir.path().join("policy.toml");
    fs::write(
        &policy_path,
        "[chain]\ntrust_roots = [\"ed25519:ff00000000000000000000000000000000000000000000000000000000000000\"]\n",
    )
    .unwrap();

    // Sign with a real key, then check verify-chain rejects because
    // the signer isn't in trust_roots.
    let priv_path = dir.path().join("priv.pem");
    let pub_path = dir.path().join("pub.pem");
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["keygen", "ed25519"])
        .args(["--out-priv", priv_path.to_str().unwrap()])
        .args(["--out-pub", pub_path.to_str().unwrap()])
        .assert()
        .success();

    let ept = dir.path().join("input.ept");
    fs::write(&ept, "// <( BEGIN PUBLIC )>\nhi\n// <( END PUBLIC )>\n").unwrap();

    // Produce an anchor signed by our key.
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--anchor"])
        .args(["--signer", priv_path.to_str().unwrap()])
        .args(["encrypt", "-w", "PUBLIC"])
        .args(["--cipher", "aes-256-siv"])
        .args(["--pbkdf", "legacy"])
        .args(["-k", "PUBLIC=pw"])
        .arg(&ept)
        .assert()
        .success();

    // verify-chain with --trust-root works (signer is the real key).
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["verify-chain"])
        .args(["--trust-root", pub_path.to_str().unwrap()])
        .arg(&ept)
        .assert()
        .success();

    // verify-chain with --policy-file pointing at trust_roots that
    // exclude the signer must fail.
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--policy-file", policy_path.to_str().unwrap()])
        .args(["verify-chain"])
        .arg(&ept)
        .assert()
        .failure();
}

#[test]
fn encrypt_with_policy_blocks_missing_capability() {
    let dir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    // Policy: WORD Agent_007 requires a Signer capability. The caller
    // in a fresh tempdir holds no signing key, so the encrypt op must
    // be refused with PolicyViolation. (Viewer/Reader are too weak —
    // Reader is implicitly granted by any existing cwd.)
    let policy_path = dir.path().join("policy.toml");
    fs::write(
        &policy_path,
        "[[word]]\nname = \"Agent_007\"\nrequired_capability = \"signer\"\n",
    )
    .unwrap();

    let res = Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--policy-file", policy_path.to_str().unwrap()])
        .args(["encrypt"])
        .args(["--cipher", "aes-256-siv"])
        .args(["-w", "Agent_007"])
        .args(["--pbkdf", "legacy"])
        .args(["-k", "Agent_007=password"])
        .arg(&ept.path)
        .assert()
        .failure();
    let stderr = std::str::from_utf8(&res.get_output().stderr).unwrap();
    assert!(
        stderr.contains("policy") || stderr.contains("capability"),
        "expected policy violation in stderr; got: {stderr}"
    );
}

#[test]
fn encrypt_with_policy_passes_when_capability_held() {
    let dir = tempdir().unwrap();
    let cas = dir.path().join("cas");
    fs::create_dir(&cas).unwrap();
    let ept = Fixture::copy("sample/test.ept");

    // Policy: Agent_007 requires Viewer — always present.
    let policy_path = dir.path().join("policy.toml");
    fs::write(
        &policy_path,
        "[[word]]\nname = \"Agent_007\"\nrequired_capability = \"viewer\"\n",
    )
    .unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--policy-file", policy_path.to_str().unwrap()])
        .args(["-c"])
        .arg(&cas)
        .args(["encrypt"])
        .args(["--cipher", "aes-256-siv"])
        .args(["-w", "Agent_007"])
        .args(["--pbkdf", "legacy"])
        .args(["-k", "Agent_007=password"])
        .arg(&ept.path)
        .assert()
        .success();
}

#[test]
fn malformed_policy_file_produces_clean_error() {
    let dir = tempdir().unwrap();
    let policy_path = dir.path().join("policy.toml");
    fs::write(&policy_path, "this is not toml {{{\n").unwrap();
    let ept = dir.path().join("input.ept");
    fs::write(&ept, "// <( BEGIN PUBLIC )>\nhi\n// <( END PUBLIC )>\n").unwrap();

    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["--policy-file", policy_path.to_str().unwrap()])
        .args(["verify-chain"])
        .arg(&ept)
        .assert()
        .failure();
}
