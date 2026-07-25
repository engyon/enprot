// Example: key generation, signing, and verification.
//
// Run: cargo run --example keygen_sign_verify

use enprot::pki::{self, SigAlgKind};

fn main() -> enprot::Result<()> {
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(enprot::Error::botan)?;

    // Generate an Ed25519 keypair
    let (priv_pem, pub_pem) = pki::keygen(SigAlgKind::Ed25519, &mut rng)?;
    println!("Generated Ed25519 keypair.");
    println!("  priv PEM: {} bytes", priv_pem.len());
    println!("  pub  PEM: {} bytes", pub_pem.len());

    // Compute the pubkey fingerprint
    let fp = enprot::capability::KeyFp::from_pem(&pub_pem)?;
    println!("  fingerprint: {}", fp);

    // Sign a message
    let msg = b"hello enprot";
    let sig = pki::sign(SigAlgKind::Ed25519, &priv_pem, msg, &mut rng)?;
    println!("\nSigned {} bytes.", msg.len());
    println!("  signature: {} bytes", sig.len());

    // Verify
    let ok = pki::verify(SigAlgKind::Ed25519, &pub_pem, msg, &sig)?;
    println!("\nVerification: {}", if ok { "VALID" } else { "INVALID" });

    // Tamper detection
    let ok_tampered = pki::verify(SigAlgKind::Ed25519, &pub_pem, b"tampered", &sig)?;
    println!(
        "Tampered message: {}",
        if ok_tampered { "VALID" } else { "INVALID" }
    );

    Ok(())
}
