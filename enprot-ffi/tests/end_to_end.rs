//! End-to-end integration test for the FFI.
//!
//! Two layers of testing:
//!
//! 1. **FFI bridge** (unit tests in `src/lib.rs`): the `json_to_argv`
//!    translator and `classify_error` mapper are tested directly.
//!
//! 2. **Pipeline dispatch** (this file): exercises the same code path
//!    the FFI takes — JSON config → argv → `enprot::app_main` — by
//!    invoking `app_main` directly. This avoids the cargo crate-name
//!    collision between `libenprot.rlib` (main crate) and the FFI's
//!    `[lib] name = "enprot"` (cdylib).
//!
//! The two layers together cover everything the FFI does: the bridge
//! builds the right argv, and app_main processes the argv correctly.

#![cfg(feature = "cli")]

use std::fs;
use std::path::PathBuf;

struct TempDir(PathBuf);
impl TempDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "enprot-ffi-test-{}-{}",
            prefix,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
    fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Build the same argv that `json_to_argv` in enprot-ffi would, then
/// invoke `enprot::app_main` on it. Mirrors exactly what the FFI does.
fn run_via_argv(argv: &[&str]) -> Result<(), String> {
    let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    enprot::app_main(argv_owned).map_err(|e| e.to_string())
}

const SAMPLE_EPT: &str = "\
hello, this is a test file
// <( BEGIN SECRET )>
hunter2
// <( END SECRET )>
more text after
";

#[test]
fn encrypt_decrypt_round_trip() {
    let dir = TempDir::new("round-trip");
    let file = dir.join("sample.ept");
    fs::write(&file, SAMPLE_EPT).unwrap();

    let file_str = file.display().to_string();
    run_via_argv(&[
        "enprot",
        "encrypt",
        "-w",
        "SECRET",
        "-k",
        "SECRET=hunter2",
        &file_str,
    ])
    .expect("encrypt should succeed");

    let encrypted = fs::read_to_string(&file).unwrap();
    assert!(
        encrypted.contains("ENCRYPTED SECRET"),
        "encrypted = {encrypted}"
    );
    assert!(
        encrypted.contains("DATA "),
        "missing DATA line: {encrypted}"
    );
    assert!(
        !encrypted.contains("hunter2"),
        "plaintext leaked into encrypted file: {encrypted}"
    );
    assert!(encrypted.contains("hello, this is a test file"));
    assert!(encrypted.contains("more text after"));

    run_via_argv(&[
        "enprot",
        "decrypt",
        "-w",
        "SECRET",
        "-k",
        "SECRET=hunter2",
        &file_str,
    ])
    .expect("decrypt should succeed");

    let decrypted = fs::read_to_string(&file).unwrap();
    assert_eq!(
        decrypted, SAMPLE_EPT,
        "decrypt should reproduce the original file verbatim"
    );
}

#[test]
fn store_fetch_round_trip() {
    let dir = TempDir::new("store-fetch");
    let file = dir.join("sample.ept");
    let cas = dir.join("cas");
    fs::create_dir_all(&cas).unwrap();
    fs::write(&file, SAMPLE_EPT).unwrap();

    let file_str = file.display().to_string();
    let cas_str = cas.display().to_string();

    run_via_argv(&[
        "enprot",
        "store",
        "-w",
        "SECRET",
        "-k",
        "SECRET=hunter2",
        "-c",
        &cas_str,
        &file_str,
    ])
    .expect("store should succeed");

    let stored = fs::read_to_string(&file).unwrap();
    assert!(stored.contains("STORED SECRET"), "stored = {stored}");
    assert!(
        !stored.contains("hunter2"),
        "plaintext not stripped: {stored}"
    );

    let entries: Vec<_> = fs::read_dir(&cas).unwrap().collect();
    assert!(!entries.is_empty(), "CAS should contain stored blob(s)");

    run_via_argv(&[
        "enprot",
        "fetch",
        "-w",
        "SECRET",
        "-k",
        "SECRET=hunter2",
        "-c",
        &cas_str,
        &file_str,
    ])
    .expect("fetch should succeed");

    let fetched = fs::read_to_string(&file).unwrap();
    assert_eq!(fetched, SAMPLE_EPT);
}
