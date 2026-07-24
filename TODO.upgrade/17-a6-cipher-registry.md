# A6 — Cipher registry (deferred)

## Problem

`cipher::encryption(alg)` and `cipher::decryption(alg)` use a `match`
on the algorithm name to dispatch between BotanCipher and
AesGcmSivCipher. Adding a new cipher backend adds a match arm.

## Approach (deferred)

Replace the match with a `phf::Map<&'static str, CipherCtor>` registry:

```rust
type CipherCtor = fn(CipherDirection) -> Result<Box<dyn SymmetricCipher>>;

static CIPHER_REGISTRY: phf::Map<&'static str, CipherCtor> = phf_map! {
    "aes-256-siv"     => botan_aes_256_siv,
    "aes-256-gcm"     => botan_aes_256_gcm,
    "aes-256-gcm-siv" => rustcrypto_aes_256_gcm_siv,
};
```

## Why deferred

Five ciphers is below the threshold where a registry pays off. The
match arms are 1-line each, compiler-checked, and easy to read. The
`-det` suffix handling would still need to be in the dispatcher
(stripping the suffix before registry lookup).

Revisit when we add ~3 more cipher backends (e.g. ChaCha20-Poly1305,
AES-256-XTS, etc.).
