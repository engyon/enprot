// Integration tests for `enprot clean` / `smudge` / `textconv`
// (TODO.roadmap/45). These are git filter protocols: stdin → stdout.

use assert_cmd::Command;
use tempfile::tempdir;

const PLAINTEXT: &str = "hello smudge world\nsecond line\n";

#[test]
fn clean_smudge_round_trip_recovers_original_plaintext() {
    // Clean: plaintext → EPT ciphertext (stdout).
    let cleaned = Command::cargo_bin("enprot")
        .unwrap()
        .args(["clean", "-w", "demo", "-k", "demo=pw"])
        .write_stdin(PLAINTEXT)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let cleaned_str = String::from_utf8(cleaned).unwrap();
    assert!(
        cleaned_str.contains("ENCRYPTED demo"),
        "clean should emit an ENCRYPTED block: got {cleaned_str}"
    );

    // Smudge: EPT ciphertext → plaintext.
    let smudged = Command::cargo_bin("enprot")
        .unwrap()
        .args(["smudge", "-w", "demo", "-k", "demo=pw"])
        .write_stdin(cleaned_str.as_bytes())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let smudged_str = String::from_utf8(smudged).unwrap();
    assert_eq!(smudged_str, PLAINTEXT);
}

#[test]
fn textconv_is_alias_for_smudge() {
    let cleaned = Command::cargo_bin("enprot")
        .unwrap()
        .args(["clean", "-w", "demo", "-k", "demo=pw"])
        .write_stdin(PLAINTEXT)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let smudged = Command::cargo_bin("enprot")
        .unwrap()
        .args(["textconv", "-w", "demo", "-k", "demo=pw"])
        .write_stdin(cleaned.as_slice())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(String::from_utf8(smudged).unwrap(), PLAINTEXT);
}

#[test]
fn clean_uses_env_var_when_no_k_flag() {
    // Git filters can't pass -k on every invocation; ENPROPT_KEY is
    // the documented workaround.
    let cleaned = Command::cargo_bin("enprot")
        .unwrap()
        .env("ENPROPT_KEY", "demo=pw")
        .args(["clean", "-w", "demo"])
        .write_stdin(PLAINTEXT)
        .assert()
        .success();
    let s = String::from_utf8(cleaned.get_output().stdout.clone()).unwrap();
    assert!(s.contains("ENCRYPTED demo"));
}

#[test]
fn clean_without_password_fails_loudly() {
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["clean", "-w", "demo"])
        .write_stdin(PLAINTEXT)
        .assert()
        .failure();
}

#[test]
fn smudge_with_wrong_password_fails() {
    let cleaned = Command::cargo_bin("enprot")
        .unwrap()
        .args(["clean", "-w", "demo", "-k", "demo=correct"])
        .write_stdin(PLAINTEXT)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    Command::cargo_bin("enprot")
        .unwrap()
        .args(["smudge", "-w", "demo", "-k", "demo=wrong"])
        .write_stdin(cleaned.as_slice())
        .assert()
        .failure();
}

#[test]
fn clean_emits_det_aead_by_default_for_diff_stability() {
    // Deterministic AEAD with a fixed-salt PBKDF means same
    // plaintext+password → identical ciphertext, so git diffs are
    // stable across re-clones. The `clean` filter doesn't auto-pick
    // legacy PBKDF (callers should opt in), so the test pins it
    // explicitly — this is the recipe docs/schemas recommends.
    let run = || {
        Command::cargo_bin("enprot")
            .unwrap()
            .args(["clean", "-w", "demo", "-k", "demo=pw", "--pbkdf", "legacy"])
            .write_stdin(PLAINTEXT)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    let a = String::from_utf8(run()).unwrap();
    let b = String::from_utf8(run()).unwrap();
    assert_eq!(
        a, b,
        "det-AEAD + legacy PBKDF must produce identical output across runs; got:\n{a}\n---\n{b}"
    );
    assert!(a.contains("aes-256-gcm-siv-det"));
}

#[test]
fn init_git_scaffolds_gitattributes() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .current_dir(dir.path())
        .args(["init", "--git"])
        .assert()
        .success();
    let attrs = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert!(attrs.contains("filter=enprot"), "got: {attrs}");
    assert!(attrs.contains("diff=enprot"));
    assert!(attrs.contains("merge=enprot"));
}
