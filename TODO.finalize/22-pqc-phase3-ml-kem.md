# PQC Phase 3 — ML-KEM-768 multi-recipient encryption

## Why

Today's encryption is password-based: every recipient needs the same
WORD password. That doesn't scale — sharing a password widely defeats
the compartmentalization. ML-KEM-768 (FIPS 203) lets each recipient
publish a public key; encryptors wrap the per-file AES key per
recipient.

This is the asymmetric-encryption track. Pairs with TODO 21
(signatures) to give enprot a complete PQ asymmetric story.

## Scope

1. Extend `src/pki.rs`:
   ```rust
   pub enum KemAlgKind { MlKem768, MlKem1024 }
   pub fn encapsulate(alg, pub_pem, rng) -> Result<(shared_key, ciphertext)>
   pub fn decapsulate(alg, priv_pem, ciphertext) -> Result<shared_key>
   ```
2. Add `ml_kem` to `ci/botan-modules`
3. `encrypt` accepts `--recipient <pub.pem>` (repeatable). Each
   recipient gets an ML-KEM ciphertext wrapping the per-file AES key.
4. New directive type at file head:
   ```
   // <( KEY-RECIPIENTS )>
   // alg=ML-KEM-768
   // 9f3a7b...:ciphertext-base64
   // 1c8d2e...:ciphertext-base64
   // <( END KEY-RECIPIENTS )>
   ```
5. `decrypt` with `--key-file <priv.pem>` extracts the matching
   recipient ciphertext, decapsulates, recovers AES key, decrypts
6. Tests:
   - keygen → encapsulate → decapsulate round-trip
   - decrypt with wrong privkey fails
   - multi-recipient: encrypt to 3 recipients, decrypt with any one
   - decrypt with no recipient key fails

## Compatibility

- Existing password-based encryption continues to work
- A file can have both: `KEY-RECIPIENTS` for KEM recipients AND
  `-k WORD=pwd` for password recipients (rare; useful for transition)

## Out of scope

- HPKE (RFC 9180). Defer; raw ML-KEM is sufficient.
- ECC hybrid (X25519+ML-KEM). TODO 23.

## Acceptance criteria

- `enprot encrypt --recipient pub1.pem --recipient pub2.pem file`
  produces a `KEY-RECIPIENTS` block
- Decrypt works with either recipient's privkey
- Wrong key fails cleanly
- README has a multi-recipient example
