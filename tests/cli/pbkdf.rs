extern crate assert_cmd;
extern crate predicates;
extern crate tempfile;

use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use std::time::Instant;
use tempfile::tempdir;

use Fixture;

#[test]
fn pbkdf_cache() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");
    let out = Fixture::blank("out.ept");
    const MSEC: &str = "10";
    const SAMPLE_COUNT: u32 = 3;
    let (encms_cache, encms_nocache, decms_cache, decms_nocache): (u32, u32, u32, u32);
    let mut elapsed_ms: u32 = 0;

    // with pbkdf cache
    for _ in 0..SAMPLE_COUNT {
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-e")
            .arg("Agent_007")
            .arg("--pbkdf")
            .arg("argon2")
            .arg("--pbkdf-msec")
            .arg(MSEC)
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&ept.path)
            .arg("-o")
            .arg(&out.path)
            .assert()
            .success();
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    encms_cache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;
    // check output
    assert!(&fs::read_to_string(&out.path).unwrap().contains("$argon2$"));
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap(),
    );
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let dec = Fixture::blank("dec.ept");
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-d")
            .arg("Agent_007")
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&out.path)
            .arg("-o")
            .arg(&dec.path)
            .assert()
            .success();
        elapsed_ms += now.elapsed().as_millis() as u32;
        assert_eq!(
            &fs::read_to_string(&ept.path).unwrap(),
            &fs::read_to_string(&dec.path).unwrap()
        );
    }
    decms_cache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    // without pbkdf cache
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-e")
            .arg("Agent_007")
            .arg("--pbkdf")
            .arg("argon2")
            .arg("--pbkdf-msec")
            .arg(MSEC)
            .arg("--pbkdf-disable-cache")
            .arg("-k")
            .arg("Agent_007=password")
            .arg(&ept.path)
            .arg("-o")
            .arg(&out.path)
            .assert()
            .success();
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    encms_nocache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;
    // check output
    assert!(&fs::read_to_string(&out.path).unwrap().contains("$argon2$"));
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap(),
    );
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let dec = Fixture::blank("dec.ept");
        let now = Instant::now();
        Command::cargo_bin("enprot")
            .unwrap()
            .arg("-c")
            .arg(casdir.path())
            .arg("-d")
            .arg("Agent_007")
            .arg("-k")
            .arg("Agent_007=password")
            .arg("--pbkdf-disable-cache")
            .arg(&out.path)
            .arg("-o")
            .arg(&dec.path)
            .assert()
            .success();
        elapsed_ms += now.elapsed().as_millis() as u32;
        assert_eq!(
            &fs::read_to_string(&ept.path).unwrap(),
            &fs::read_to_string(&dec.path).unwrap()
        );
    }
    decms_nocache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    // using cache should be consistently quicker
    assert!(encms_cache < encms_nocache);
    assert!(decms_cache < decms_nocache);
}
