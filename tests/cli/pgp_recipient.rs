// SPIKE (replaced by real pgp-recipient tests): prove the rnp-rs
// encryption roundtrip across contexts — keygen, armored export,
// pub-only import, encrypt-to-pub, secret import, decrypt — the seam
// the OpenPGP recipient path builds on.

use rnp::key::{ExportFlags, LoadSaveFlags};
use rnp::{Algorithm, Context, Decryptor, Encryptor, KeyBuilder, KeyUsage, Output};

#[test]
fn rnp_encrypt_roundtrip() {
    let gen_ctx = Context::new().unwrap();
    let key = KeyBuilder::new(Algorithm::Rsa)
        .bits(2048)
        .userid("spike <spike@example.com>")
        .add_usage(KeyUsage::EncryptComms)
        .build(&gen_ctx)
        .unwrap();
    let pub_arm = key
        .export(ExportFlags::ARMORED | ExportFlags::PUBLIC)
        .unwrap();
    let sec_arm = key
        .export(ExportFlags::ARMORED | ExportFlags::SECRET)
        .unwrap();
    assert!(String::from_utf8_lossy(&pub_arm).contains("BEGIN PGP PUBLIC KEY"));

    // Fresh context holding ONLY the public key: encrypt the CEK.
    let ctx = Context::new().unwrap();
    ctx.load_keys(rnp::KeyringFormat::Gpg, &pub_arm, LoadSaveFlags::PUBLIC)
        .unwrap();
    let recipient = ctx
        .find_key(rnp::KeyIdentifier::Userid("spike <spike@example.com>"))
        .unwrap()
        .expect("imported pub key");
    let cek = b"0123456789abcdef0123456789abcdef".to_vec();
    let mut ct = Output::to_memory().unwrap();
    Encryptor::new(&ctx, &cek)
        .unwrap()
        .add_recipient(&recipient)
        .build(&mut ct)
        .unwrap();
    let ciphertext = ct.into_bytes().unwrap();
    assert!(!ciphertext.is_empty() && ciphertext != cek);

    // Import the secret key; decrypt back to the CEK.
    ctx.load_keys(rnp::KeyringFormat::Gpg, &sec_arm, LoadSaveFlags::SECRET)
        .unwrap();
    let result = Decryptor::new(&ctx, &ciphertext).build().unwrap();
    assert_eq!(result.plaintext(), cek.as_slice());
}

// Full CLI roundtrip: --pgp-pubkey recipients receive the CEK;
// decrypt works password-less via --key-file with the secret.
#[test]
fn encrypt_to_pgp_recipient_and_decrypt_with_secret() {
    use rnp::key::ExportFlags;
    use rnp::{Algorithm, Context, KeyBuilder, KeyUsage};
    use std::fs;

    let ctx = Context::new().unwrap();
    let key = KeyBuilder::new(Algorithm::Rsa)
        .bits(2048)
        .userid("e2e <e2e@example.com>")
        .add_usage(KeyUsage::EncryptComms)
        .build(&ctx)
        .unwrap();
    let pub_arm = String::from_utf8(
        key.export(ExportFlags::ARMORED | ExportFlags::PUBLIC)
            .unwrap(),
    )
    .unwrap();
    let sec_arm = String::from_utf8(
        key.export(ExportFlags::ARMORED | ExportFlags::SECRET)
            .unwrap(),
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("doc.ept");
    fs::write(
        &doc,
        "// <( BEGIN W )>\npgp-secret payload\n// <( END W )>\n",
    )
    .unwrap();
    let pub_path = dir.path().join("pub.asc");
    let sec_path = dir.path().join("sec.asc");
    fs::write(&pub_path, &pub_arm).unwrap();
    fs::write(&sec_path, &sec_arm).unwrap();

    use assert_cmd::Command;
    Command::cargo_bin("enprot")
        .unwrap()
        .args([
            "encrypt",
            "-w",
            "W",
            "-k",
            "W=pw",
            "--cipher",
            "aes-256-siv",
            "--pgp-pubkey",
        ])
        .arg(&pub_path)
        .arg(&doc)
        .assert()
        .success();

    let content = fs::read_to_string(&doc).unwrap();
    let has_wrap = content
        .lines()
        .any(|l| l.contains("pgp-") && l.contains("-wrap"));
    assert!(has_wrap, "pgp recipient wrap extfield missing:\n{content}");

    // Passwordless decrypt via the PGP secret key.
    let dec = dir.path().join("dec.ept");
    fs::copy(&doc, &dec).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["decrypt", "-w", "W", "--key-file"])
        .arg(&sec_path)
        .arg(&dec)
        .assert()
        .success();
    assert!(
        fs::read_to_string(&dec)
            .unwrap()
            .contains("pgp-secret payload")
    );
}

// A secret key that is NOT a recipient must not decrypt.
#[test]
fn wrong_pgp_secret_key_fails() {
    use rnp::key::ExportFlags;
    use rnp::{Algorithm, Context, KeyBuilder, KeyUsage};
    use std::fs;

    let mk = || {
        let ctx = Context::new().unwrap();
        let key = KeyBuilder::new(Algorithm::Rsa)
            .bits(2048)
            .userid("k <k@example.com>")
            .add_usage(KeyUsage::EncryptComms)
            .build(&ctx)
            .unwrap();
        (
            String::from_utf8(
                key.export(ExportFlags::ARMORED | ExportFlags::PUBLIC)
                    .unwrap(),
            )
            .unwrap(),
            String::from_utf8(
                key.export(ExportFlags::ARMORED | ExportFlags::SECRET)
                    .unwrap(),
            )
            .unwrap(),
        )
    };
    let (pub1, _sec1) = mk();
    let (_pub2, sec2) = mk();

    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("doc.ept");
    fs::write(&doc, "// <( BEGIN W )>\nx\n// <( END W )>\n").unwrap();
    let p1 = dir.path().join("p1.asc");
    let s2 = dir.path().join("s2.asc");
    fs::write(&p1, &pub1).unwrap();
    fs::write(&s2, &sec2).unwrap();

    use assert_cmd::Command;
    Command::cargo_bin("enprot")
        .unwrap()
        .args([
            "encrypt",
            "-w",
            "W",
            "-k",
            "W=pw",
            "--cipher",
            "aes-256-siv",
            "--pgp-pubkey",
        ])
        .arg(&p1)
        .arg(&doc)
        .assert()
        .success();

    let dec = dir.path().join("dec.ept");
    fs::copy(&doc, &dec).unwrap();
    Command::cargo_bin("enprot")
        .unwrap()
        .args(["decrypt", "-w", "W", "--key-file"])
        .arg(&s2)
        .arg(&dec)
        .assert()
        .failure();
}
