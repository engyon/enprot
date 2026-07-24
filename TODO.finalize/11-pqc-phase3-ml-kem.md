# PQC Phase 3 — ML-KEM (Kyber) key encapsulation

## Goal

Add NIST FIPS 203 ML-KEM-768 as a post-quantum KEM, exposing
public-key encryption for WORD passwords and session keys. rnp ships
ML-KEM-768 as the PQ leg of their KEM.

## Why

Symmetric-only encryption (the current model) scales poorly for teams:
every recipient needs the same password. A KEM lets each recipient
publish a public key; encryptors encapsulate a one-time AES key per
recipient. This unlocks multi-recipient EPT files without sharing
secrets.

## Scope

1. Add `ml_kem`, `kyber`, `hpke` (possibly) to `ci/botan-modules`.
2. Extend `src/pki.rs`:
   - `KeyEncapsulation` wrapper around Botan's KEM API
     (`PK_KEM_Encryptor` / `PK_KEM_Decryptor`).
   - `fn encapsulate(pub_pem, rng) -> (shared_key, ciphertext)`.
   - `fn decapsulate(priv_pem, ciphertext) -> shared_key`.
3. New CLI subcommand:
   - `enprot keygen MlKem768 --out-priv priv.pem --out-pub pub.pem`
   - Extend `enprot encrypt` with `--recipient PUBKEY.pem` (repeatable).
     Each recipient gets an ML-KEM ciphertext wrapping the per-file
     AES key. Stored in a new `KEY-RECIPIENTS` block at the top of the
     EPT file.
4. Tests:
   - keygen→encapsulate→decapsulate round-trip.
   - decrypt with wrong privkey fails.
   - multi-recipient encrypt + decrypt-with-any-recipient.

## Out of scope

- HPKE (RFC 9180) mode. Defer; ML-KEM raw is sufficient for v1.
- ECC hybrid (X25519+ML-KEM-768). That's Phase 4.

## Wire format sketch

```
// <( KEY-RECIPIENTS )>
// alg=ML-KEM-768
// 000102...:ciphertext-for-recipient-1
// 0304...:ciphertext-for-recipient-2
// <( END KEY-RECIPIENTS )>
```

The AES key wrapped by these is the per-file key derived from PBKDF or
generated fresh if `--recipient` is used (in which case `-k WORD=pwd`
is forbidden — the key comes from the KEM, not a password).

## Acceptance criteria

- `cargo test` includes KEM round-trip and multi-recipient tests.
- README.adoc "Asymmetric encryption" section documents the new flow.
