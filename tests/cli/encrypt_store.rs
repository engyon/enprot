extern crate assert_cmd;
extern crate crypto;
extern crate predicates;
extern crate tempfile;

use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use Fixture;

#[test]
fn encrypt_store_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-agent007.ept").unwrap()
    );
    for hashval in vec![
        "1749eaec9b40e6757ddd29b58002b01cf210e46119a8345421de80c6a3dd672a",
        "7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2",
    ] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
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
fn encrypt_store_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-geheim.ept").unwrap()
    );
    for hashval in vec!["ab664af9ef8ed0a7a542c4bcc0d2d2bf06973038d83ddbfcdd031eb80a308d5a"] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("GEHEIM")
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
fn encrypt_store_both_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
        .arg("Agent_007,GEHEIM")
        .arg("--pbkdf")
        .arg("legacy")
        .arg("-k")
        .arg("Agent_007=password,GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-store-both.ept").unwrap()
    );
    for hashval in vec![
        "7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2",
        "ab664af9ef8ed0a7a542c4bcc0d2d2bf06973038d83ddbfcdd031eb80a308d5a",
    ] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007,GEHEIM")
        .arg("-k")
        .arg("Agent_007=password,GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_store_agent007_geheim() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-agent007.ept").unwrap()
    );
    for hashval in vec![
        "1749eaec9b40e6757ddd29b58002b01cf210e46119a8345421de80c6a3dd672a",
        "7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2",
    ] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-agent007-geheim.ept").unwrap()
    );
    for hashval in vec!["86117980a54565a74cc5195865827aab44cfafc138e723e3a409631384d74ee2"] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007,GEHEIM")
        .arg("-k")
        .arg("Agent_007=password,GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    // TODO: bug? We do not recursively decrypt, so this has to be called twice
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("Agent_007,GEHEIM")
        .arg("-k")
        .arg("Agent_007=password,GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&ept.source).unwrap()
    );
}

#[test]
fn encrypt_store_geheim_agent007() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-geheim.ept").unwrap()
    );
    for hashval in vec!["ab664af9ef8ed0a7a542c4bcc0d2d2bf06973038d83ddbfcdd031eb80a308d5a"] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
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
        &fs::read_to_string("test-data/test-encrypt-store-geheim-agent007.ept").unwrap()
    );
    for hashval in vec!["7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2"] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
        .arg("GEHEIM")
        .arg("-k")
        .arg("GEHEIM=password")
        .arg(&ept.path)
        .assert()
        .success();
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
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
fn encrypt_store_agent007_argon2() {
    let casdir = tempdir().unwrap();
    let ept = Fixture::copy("sample/test.ept");

    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("--encrypt-store")
        .arg("Agent_007")
        .arg("--pbkdf")
        .arg("argon2")
        .arg("--pbkdf-params")
        .arg("t=1,p=1,m=16")
        .arg("--pbkdf-salt")
        .arg("0102030405060708")
        .arg("-k")
        .arg("Agent_007=password")
        .arg(&ept.path)
        .assert()
        .success();
    assert_eq!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string("test-data/test-encrypt-store-agent007-argon2.ept").unwrap()
    );
    for hashval in vec![
        "03596e1743f8d7e969979d5e4f9f8bf41bca02c723f84a2f12193b2196077805",
        "b30ccd443bae74afc464822857fad6974f0cbb12197368494cc311441c74ea20",
    ] {
        let mut hash = Sha3::sha3_256();
        hash.input(&fs::read(casdir.path().join(hashval)).unwrap());
        assert_eq!(hash.result_str(), hashval,);
    }
    Command::cargo_bin("enprot")
        .unwrap()
        .arg("-c")
        .arg(casdir.path())
        .arg("-d")
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
