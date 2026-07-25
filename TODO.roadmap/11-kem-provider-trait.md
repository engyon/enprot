# 11 — KemProvider trait: abstraction over encryption mechanisms

**Priority**: P0
**Status**: specified

## Problem

Today's encryption is password-based: PBKDF derives an AES key from a
caller-supplied password. Adding ML-KEM (public-key encryption, roadmap 30)
or threshold encryption (roadmap 21) requires a new code path. The
`--recipient` flag and the KEY-RECIPIENTS wire format need to know what
kind of recipient they're targeting.

## Solution

A trait that abstracts how per-file AES keys are derived:

```rust
/// How the per-file AES key is produced for a WORD encryption.
/// Implementations:
/// - [`PasswordKem`] — PBKDF over a password (today's behavior)
/// - [`MlKemProvider`] — single-party ML-KEM encapsulation (roadmap 30)
/// - [`ConfiumKemProvider`] — threshold ML-KEM via Confium (roadmap 21)
///
/// For password encryption, the "KEM" is conceptual: PBKDF derives
/// the key directly. For public-key encryption, encapsulate produces
/// a ciphertext that decapsulate (on the recipient side) converts
/// back to the same key.
pub trait KemProvider {
    /// The encryption side: produce the AES key + a recipient-specific
    /// ciphertext that the recipient can use to recover the key.
    /// Returns (aes_key, recipient_ciphertext, recipient_fingerprint).
    fn encapsulate(
        &self,
        rng: &mut botan::RandomNumberGenerator,
    ) -> Result<(Vec<u8>, Vec<u8>, KeyFp)>;

    /// The decryption side: recover the AES key from the recipient
    /// ciphertext. For single-party KEM, uses the privkey directly.
    /// For threshold KEM, delegates to Confium (K-of-N decapsulation).
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// The recipient key fingerprint (group key for threshold).
    fn fingerprint(&self) -> Result<KeyFp>;
}
```

## PasswordKem (existing behavior, wrapped)

```rust
/// Today's PBKDF path. Not really a "KEM" — it's a KDF — but it
/// implements the same interface so the encryption pipeline doesn't
/// need to branch on "password vs public-key".
pub struct PasswordKem {
    word: String,
    password: String,
    pbkdf_opts: PBKDFOptions,
}

impl KemProvider for PasswordKem {
    fn encapsulate(&self, rng) -> Result<(Vec<u8>, Vec<u8>, KeyFp)> {
        // Derive key via PBKDF. The "ciphertext" is the PHC string
        // (salt + params) stored in the extfield.
        let key = pbkdf::derive_key(...)?;
        let phc_string = pbkdf::format_phc(...)?;
        // Fingerprint = SHA3-256 of the WORD name (not secret-derived)
        Ok((key, phc_string.into_bytes(), KeyFp::from_word(&self.word)))
    }
    fn decapsulate(&self, phc_bytes) -> Result<Vec<u8>> {
        let phc = std::str::from_utf8(phc_bytes)?;
        pbkdf::derive_key_from_phc(&self.password, phc)
    }
}
```

## MlKemProvider (roadmap 30)

```rust
pub struct MlKemProvider {
    pub_pem: String,  // encapsulate side
    priv_pem: Option<String>,  // decapsulate side (None if encrypt-only)
}
```

## ConfiumKemProvider (roadmap 21)

```rust
pub struct ConfiumKemProvider {
    endpoint: String,
    session_id: String,
    quorum: usize,
}
```

## CLI integration

The encrypt pipeline becomes:
```rust
let provider: Box<dyn KemProvider> = if let Some(recipient) = &recipient_flag {
    if recipient.starts_with("confium://") {
        Box::new(ConfiumKemProvider::from_uri(recipient)?)
    } else {
        Box::new(MlKemProvider::from_pubkey(recipient)?)
    }
} else {
    Box::new(PasswordKem::new(word, password, pbkdf_opts))
};

let (aes_key, recipient_ct, fp) = provider.encapsulate(rng)?;
// encrypt content with aes_key
// store recipient_ct + fp in KEY-RECIPIENTS block
```

## Design constraints

- **OCP**: new encryption mechanisms = new `impl KemProvider`
- **MECE**: password, single-party KEM, and threshold KEM don't overlap
- **DRY**: the encryption pipeline is one `provider.encapsulate()` call
- The wire format (KEY-RECIPIENTS block, pbkdf: extfield) stays unchanged
- Threshold and single-party KEM produce the same wire shape
