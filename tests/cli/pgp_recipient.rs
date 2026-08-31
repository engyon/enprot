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
    ctx.load_keys(
        rnp::KeyringFormat::Gpg,
        &pub_arm,
        LoadSaveFlags::PUBLIC,
    )
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
    ctx.load_keys(
        rnp::KeyringFormat::Gpg,
        &sec_arm,
        LoadSaveFlags::SECRET,
    )
    .unwrap();
    let result = Decryptor::new(&ctx, &ciphertext).build().unwrap();
    assert_eq!(result.plaintext(), cek.as_slice());
}
