# 56 — HSM / TPM / Secure Enclave integration

**Priority**: P3
**Status**: specified

## Problem

enprot's signing operations (`pki::sign`, anchor signing, audit-log
signing) load private keys from PEM files. The private key bytes
live in process memory, in plaintext, until the process exits. For
high-assurance deployments:

- An attacker with dump access can extract the key.
- An attacker who compromises the signing process has the key.
- Key rotation requires distributing new PEM files to every signer.

Hardware-backed key storage addresses this:

- **HSM** (Hardware Security Module): dedicated cryptographic device.
  Keys never leave the device; signing happens inside.
- **TPM 2.0** (Trusted Platform Module): motherboard-attached crypto
  chip. Standard on modern servers + laptops.
- **Secure Enclave** (macOS): dedicated secure coprocessor. Keys
  generated in the enclave can be marked non-extractable.
- **Android Keystore** / **iOS Secure Enclave**: equivalent on
  mobile.

With hardware-backed keys, the private key never enters process
memory. The signing operation is delegated to the device.

## Goals

- A `Signer` abstraction that can be backed by:
  - **Software** (current PEM-based path)
  - **PKCS#11 HSM** (YubiHSM, Thales, etc.)
  - **TPM 2.0** (via `tss` crate)
  - **macOS Secure Enclave** (via `Security.framework`)
- The `pki::sign` API takes a `&dyn Signer`; the backend is
  abstracted.
- A `--signer-backend pkcs11|tpm|enclave|software` CLI flag.
- Documented setup for each backend.

## Goals (non-goals)

- Hardware-backed encryption (not just signing). Out of scope —
  symmetric crypto is fast enough in software.
- Remote HSMs over the network (defer; covered by a custom PKCS#11
  driver if needed).

## Design

### Signer trait

```rust
// src/pki.rs (extended)

pub trait Signer: Send + Sync {
    /// Returns the algorithm this signer produces.
    fn algorithm(&self) -> SigAlgKind;

    /// Returns the public key (PEM-encoded) corresponding to the
    /// stored private key. Used for fingerprinting + verification.
    fn public_key_pem(&self) -> Result<String>;

    /// Sign `msg` and return the raw signature bytes. The signature
    /// format matches `algorithm()` (Ed25519 raw, composite has
    /// length-prefixed legs).
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

// Existing PEM-based signer
pub struct SoftwareSigner {
    privkey_pem: String,
    pubkey_pem: String,
    alg: SigAlgKind,
}

impl Signer for SoftwareSigner {
    fn algorithm(&self) -> SigAlgKind { self.alg }
    fn public_key_pem(&self) -> Result<String> { Ok(self.pubkey_pem.clone()) }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        sign(self.alg, &self.privkey_pem, msg)
    }
}
```

### PKCS#11 backend

```rust
// src/pki/pkcs11.rs (new, behind "pkcs11" feature)
pub struct Pkcs11Signer {
    module: cryptoki::Pkcs11,
    session: cryptoki::Session,
    key_handle: cryptoki::ObjectHandle,
    mech: cryptoki::Mechanism,
    alg: SigAlgKind,
    pubkey_pem: String,
}

impl Signer for Pkcs11Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.session.sign(&self.key_handle, &self.mech, msg)
            .map_err(|e| Error::SignatureVerify {
                key_id: format!("pkcs11 key {:?}: {}", self.key_handle, e),
            })
    }
    // ...
}
```

Setup:

```toml
# .enprot/signers.toml
[[signer]]
id = "prod-hsm"
backend = "pkcs11"
module = "/usr/lib/softhsm/libsofthsm2.so"
slot = 0
pin_env = "PKCS11_PIN"  # read PIN from env, not config
key_label = "enprot-prod"
```

### TPM 2.0 backend

```rust
// src/pki/tpm.rs (new, behind "tpm" feature)
pub struct TpmSigner {
    ctx: tss_esapi::Context,
    key_handle: tss_esapi::handles::KeyHandle,
    alg: SigAlgKind,
    pubkey_pem: String,
}
```

Setup uses `tcsd` (TPM daemon); the key is referenced by handle,
not PEM bytes.

### macOS Secure Enclave backend

```rust
// src/pki/enclave.rs (new, behind "enclave" feature, macOS-only)
pub struct EnclaveSigner {
    key: security_framework::key::SecureEnclaveKey,
    alg: SigAlgKind,
    pubkey_pem: String,
}
```

Uses `Security.framework`'s `SecKeyCreateRandomKey` with the
`kSecAttrTokenIDSecureEnclave` attribute.

### CLI integration

```sh
enprot attest --signer prod-hsm --signer-backend pkcs11 FILE
enprot audit-log --signer tpm-key --signer-backend tpm FILE
```

If `--signer-backend` is omitted, defaults to `software` (current
behavior).

## Implementation plan

1. Define the `Signer` trait.
2. Refactor `pki::sign` to take `&dyn Signer`.
3. Add `SoftwareSigner` wrapping the existing PEM-based path.
4. Land PKCS#11 backend behind `pkcs11` feature.
5. Land TPM backend behind `tpm` feature.
6. Land macOS Secure Enclave backend behind `enclave` feature
   (macOS-only).
7. Add `--signer-backend` CLI flag + per-backend config in
   `.enprot/signers.toml`.
8. Document setup for each backend in `docs/hardware-signing.md`.

## Test plan

- [ ] All existing signing tests pass with `SoftwareSigner`.
- [ ] PKCS#11 backend round-trips against SoftHSM2 in CI.
- [ ] TPM backend round-trips against a TPM simulator (swtpm) in CI.
- [ ] macOS Secure Enclave backend builds only on macOS.
- [ ] Documentation covers setup + key generation for each backend.

## Out of scope

- Hardware-backed symmetric encryption (out of scope — see goals).
- Network HSM protocols (KMIP) — defer; PKCS#11 covers most HSMs.
- Smart cards (PIV/CAC) — covered by PKCS#11 if the card has a driver.
- Android Keystore / iOS Secure Enclave — covered by TODO #47.
