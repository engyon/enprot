// Integration tests for `enprot init --git`: the turnkey git wiring
// (attributes + filter/diff/merge config, set surgically).

use assert_cmd::Command;
use std::fs;

fn git(args: &[&str], dir: &std::path::Path) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {:?}: {}{}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn init_git_wires_the_full_trio() {
    let dir = tempfile::tempdir().unwrap();
    git(&["init", "-q"], dir.path());
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["init", "--git", "--git-word", "ALPHA"])
        .current_dir(dir.path())
        .assert()
        .success();

    let attrs = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert!(
        attrs.contains("*.ept filter=enprot diff=enprot merge=enprot"),
        "{attrs}"
    );

    let get = |k: &str| {
        let out = std::process::Command::new("git")
            .args(["config", "--get", k])
            .current_dir(dir.path())
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(get("filter.enprot.smudge"), "enprot smudge -w ALPHA");
    assert_eq!(get("filter.enprot.clean"), "enprot clean -w ALPHA");
    assert_eq!(get("filter.enprot.required"), "false");
    assert_eq!(
        get("merge.enprot.driver"),
        "enprot merge-driver %O %A %B %P"
    );

    // Idempotent: a second run succeeds and does not duplicate the
    // attributes entry.
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["init", "--git", "--git-word", "ALPHA", "--force"])
        .current_dir(dir.path())
        .assert()
        .success();
    let attrs2 = fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
    assert_eq!(attrs2.matches("filter=enprot").count(), 1, "{attrs2}");
}
