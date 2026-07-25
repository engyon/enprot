// Example: basic encrypt/decrypt round-trip via the library API.
//
// Run: cargo run --example basic_encrypt_decrypt

use enprot::crypto::CryptoPolicyDefault;
use enprot::etree::ParseOps;

fn main() -> enprot::Result<()> {
    let casdir = tempfile::tempdir()?;
    let ept = tempfile::tempdir()?.into_path().join("test.ept");

    // Write a fixture file
    std::fs::write(&ept, "// <( BEGIN Secret )>\nplaintext\n// <( END Secret )>\n")?;

    // Encrypt
    {
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {}))?;
        paops.io.casdir = casdir.path().to_path_buf();
        paops.transforms.encrypt.insert("Secret".into());
        paops.passwords.insert("Secret".into(), "password".into());
        let content = std::fs::read_to_string(&ept)?;
        let tree = enprot::etree::parse(
            std::io::Cursor::new(content.into_bytes()),
            &mut paops,
        )?;
        let tree = enprot::etree::transform(&tree, &mut paops)?;
        let mut out = Vec::new();
        enprot::etree::tree_write(&mut out, &tree, &mut paops)?;
        std::fs::write(&ept, out)?;
    }
    println!("Encrypted. Content is now ciphertext.");

    // Decrypt
    {
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {}))?;
        paops.io.casdir = casdir.path().to_path_buf();
        paops.transforms.decrypt.insert("Secret".into());
        paops.passwords.insert("Secret".into(), "password".into());
        let content = std::fs::read_to_string(&ept)?;
        let tree = enprot::etree::parse(
            std::io::Cursor::new(content.into_bytes()),
            &mut paops,
        )?;
        let tree = enprot::etree::transform(&tree, &mut paops)?;
        let mut out = Vec::new();
        enprot::etree::tree_write(&mut out, &tree, &mut paops)?;
        std::fs::write(&ept, out)?;
    }
    println!("Decrypted. Content is back to plaintext.");
    println!("Result: {}", std::fs::read_to_string(&ept)?);

    Ok(())
}
