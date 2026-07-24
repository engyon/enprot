use crate::Fixture;
use assert_cmd::Command;
use cpu_time::ThreadTime;
use std::fs;
use tempfile::tempdir;

#[test]
fn encrypt_decrypt_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

// Was `#[cfg(unix)]` because the old rpassword 2 API didn't behave on
// Windows when stdin was piped. PR #57 replaced the reader with a
// TTY-aware path (`prompt_password_with_config` from rpassword 7), which
// is cross-platform; see TODO.issues/50-windows-stdin-test.md.
#[test]
fn encrypt_decrypt_agent007_stdin_pass() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg(&ept.path)
        .write_stdin("password\r\npassword\r\n")
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_both_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007,GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007,GEHEIM")
        .arg("-k")
        .arg("Agent_007=password")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_geheim_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim-then-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("GEHEIM")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
}

#[test]
fn encrypt_decrypt_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-geheim.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("GEHEIM")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap(),
    );
}

#[test]
fn encrypt_decrypt_agent007_default_pbkdf() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf-params") // just for speed
        .arg("m=8,t=1,p=1")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    // just make sure it selected argon2
    assert!(
        &fs::read_to_string(&ept.path)
            .unwrap()
            .contains("pbkdf:$argon2$")
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_pbkdf2() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha256")
        .arg("--pbkdf-params")
        .arg("i=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-pbkdf2.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_decrypt_agent007_pbkdf2_sha512() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("pbkdf2-sha512")
        .arg("--pbkdf-params")
        .arg("i=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-pbkdf2-sha512.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

// This test ensures that pbkdf-msec is actually utilized.
#[test]
fn encrypt_decrypt_agent007_pbkdf2_millis() {
    const SAMPLE_COUNT: u32 = 3;
    let mut elapsed_ms: u32;

    // 10ms
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let ept = Fixture::copy("sample/test.ept");
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "encrypt",
            "-w",
            "Agent_007",
            "--pbkdf",
            "pbkdf2-sha256",
            "--pbkdf-msec",
            "10",
            "-k",
            "Agent_007=password",
            &ept.path.to_str().unwrap(),
        ])
        .unwrap();
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    let avg10 = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    // 50ms
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let ept = Fixture::copy("sample/test.ept");
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "encrypt",
            "-w",
            "Agent_007",
            "--pbkdf",
            "pbkdf2-sha256",
            "--pbkdf-msec",
            "50",
            "-k",
            "Agent_007=password",
            &ept.path.to_str().unwrap(),
        ])
        .unwrap();
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    let avg50 = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    assert!(avg50 > avg10);
}

#[test]
fn encrypt_decrypt_agent007_scrypt() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("encrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("scrypt")
        .arg("--pbkdf-params")
        .arg("ln=2,p=1,r=1")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-agent007-scrypt.ept").unwrap()
    );
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("decrypt")
        .arg("-w")
        .arg("Agent_007")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}
