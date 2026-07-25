# 30 — ML-KEM (FIPS 203) multi-recipient encryption

**Priority**: P1
**Status**: specified

## Problem

Today's encryption is password-based. Every recipient needs the same
WORD password — doesn't scale. ML-KEM (Kyber) lets each recipient publish
a public key; encryptors wrap the per-file AES key per recipient.

## Solution

Extends `src/pki.rs` with `KemAlgKind`:

```rust
pub enum KemAlgKind { MlKem }
```

### Wire format: KEY-RECIPIENTS directive

```
// <( KEY-RECIPIENTS )>
// mlkem:<fp-hex>:<base64-ciphertext>
// mlkem:<fp-hex>:<base64-ciphertext>
// <( END KEY-RECIPIENTS )>
```

### CLI

```sh
# Each recipient publishes their pubkey
enprot keygen mlkem --out-pub alice.pub
enprot keygen mlkem --out-pub bob.pub

# Encrypt to multiple recipients
enprot encrypt --recipient alice.pub --recipient bob.pub \
    -w SharedDoc shared.ept

# Each recipient decrypts with their own privkey
enprot decrypt --recipient-key alice.priv shared.ept
```

### Implementation via KemProvider

`MlKemProvider` implements the `KemProvider` trait (roadmap 11). The
encrypt pipeline calls `encapsulate` once per recipient, storing each
ciphertext in the KEY-RECIPIENTS block. The decrypt pipeline finds the
matching entry by fingerprint and calls `decapsulate`.

## Botan API

```rust
// Encapsulate
let (shared_secret, ciphertext) = botan::kem_encapsulate(&pubkey)?;

// Decapsulate
let shared_secret = botan::kem_decapsulate(&privkey, &ciphertext)?;
```

Botan 3.7+ supports ML-KEM via the `ml_kem` module.

## ci/botan-modules

Add `ml_kem` to the minimized build modules list.

## Compatibility with password encryption

A file can have BOTH password encryption AND KEM recipients:
- `-k WORD=pwd` → PasswordKem path (existing)
- `--recipient pub.pem` → MlKemProvider path (new)
- Both produce the same AES key? No — they produce different keys.
  The AES key is chosen by one mechanism; the other wraps it.

Design choice: if `--recipient` is specified, the AES key is random
(generated fresh), and each recipient gets it via KEM. Password
encryption is forbidden with `--recipient` (they're alternative
mechanisms for the same WORD). If both are needed, use two separate
WORD segments.

## Acceptance criteria

- [ ] `enprot keygen mlkem` produces valid keypair
- [ ] `--recipient` produces KEY-RECIPIENTS block
- [ ] Decrypt with matching privkey recovers plaintext
- [ ] Decrypt with wrong key fails cleanly
- [ ] Multi-recipient: encrypt to 3, decrypt with any 1
- [ ] `ml_kem` added to ci/botan-modules
