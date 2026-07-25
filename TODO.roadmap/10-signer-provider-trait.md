# 10 — SignerProvider trait: abstraction over signing mechanisms

**Priority**: P0
**Status**: specified

## Problem

Today, `--signer priv.pem` is hardcoded: the CLI loads a PEM file, derives
the pubkey, computes the fingerprint, and calls `pki::sign`. This is
single-party only. Adding Confium (threshold), PKCS#11 (hardware), or any
future signing backend requires touching every call site.

## Solution

A trait that abstracts how signatures are produced:

```rust
/// How signatures are produced. Implementations:
/// - [`PemSigner`] — single-party PEM key (today's behavior)
/// - [`ConfiumSigner`] — threshold via Confium daemon (roadmap 22)
/// - [`Pkcs11Signer`] — hardware token (future)
///
/// All implementations return the same output shape: algorithm, raw
/// signature bytes, and the key fingerprint (group key for threshold;
/// individual key for single-party). The wire format is identical —
/// verifiers can't tell whether threshold was used.
pub trait SignerProvider {
    /// Sign a message. Returns (algorithm, signature, fingerprint).
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)>;

    /// The key fingerprint this provider signs under. For single-party,
    /// the individual key's fingerprint. For threshold, the group key's
    /// fingerprint.
    fn fingerprint(&self) -> Result<KeyFp>;
}

/// Single-party PEM-backed signer. Wraps today's `pki::sign` path.
pub struct PemSigner {
    priv_pem: String,
    pub_pem: String,
    alg: SigAlgKind,
    fp: KeyFp,
}

impl PemSigner {
    pub fn from_files(priv_path: &Path, alg: SigAlgKind) -> Result<Self> {
        let priv_pem = fs::read_to_string(priv_path)?;
        let botan_priv = botan::Privkey::load_pem(&priv_pem).map_err(Error::botan)?;
        let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
        let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
        let fp = KeyFp::from_pem(&pub_pem)?;
        Ok(PemSigner { priv_pem, pub_pem, alg, fp })
    }
}

impl SignerProvider for PemSigner {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
        let sig = pki::sign(self.alg, &self.priv_pem, msg, &mut rng)?;
        Ok((self.alg, sig, self.fp))
    }
    fn fingerprint(&self) -> Result<KeyFp> { Ok(self.fp) }
}
```

## CLI integration

`--signer` accepts a URI scheme:
- `--signer priv.pem` → `PemSigner::from_files(priv.pem, Ed25519)`
- `--signer confium://session-id` → `ConfiumSigner::new(...)` (roadmap 22)
- `--signer pkcs11://token-id` → `Pkcs11Signer::new(...)` (future)

```rust
fn parse_signer(s: &str, alg: SigAlgKind) -> Result<Box<dyn SignerProvider>> {
    if s.starts_with("confium://") {
        Ok(Box::new(ConfiumSigner::from_uri(s)?))
    } else if s.starts_with("pkcs11://") {
        Ok(Box::new(Pkcs11Signer::from_uri(s)?))
    } else {
        Ok(Box::new(PemSigner::from_files(Path::new(s), alg)?))
    }
}
```

## Refactor scope

1. Extract `SignerProvider` trait in `src/signer.rs` (or `src/provider/signer.rs`)
2. `PemSigner` wraps the existing priv-pem loading + pubkey derivation
3. `--anchor` flag calls `provider.sign(signing_bytes)` instead of inline `Anchor::sign()`
4. `audit-log` mode calls `provider.sign()` in the loop
5. Tests: PemSigner round-trip (same as today's tests, just through the trait)

## Design constraints

- **OCP**: new signer backends = new `impl SignerProvider`, zero changes to callers
- **MECE**: signers don't overlap — each has a distinct URI scheme
- **DRY**: the signing path is one `provider.sign()` call, not duplicated
- **Performance**: PemSigner pre-loads the pubkey at construction (once per invocation, not once per anchor in audit-log mode)
