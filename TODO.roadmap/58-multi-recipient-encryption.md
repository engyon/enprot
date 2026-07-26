# 58 — Multi-recipient encryption (local variant of TODO.roadmap/21)

**Priority**: P1
**Status**: specified

## Problem

`enprot encrypt` today only supports password-based encryption
(PBKDF over a caller-supplied password). For pubkey-based
confidentiality — encrypt once, decrypt with any of N privkeys —
there's no path. This blocks the capability-model promise of
"encrypt to a recipient's pubkey, not a shared password".

## Solution

New encrypt mode: caller passes one or more `--recipient
pub.pem` flags. Encryption generates a fresh AES-256 session
key, encrypts the payload with it, and ML-KEM-encapsulates the
session key to each recipient. The wire format records the
recipient set and one ciphertext per recipient.

### Wire format (Encrypted extfields)

Single-recipient (new — backwards-incompatible, requires
opt-in via `--recipient`):
```
recipients: mlkem:1c8d2e...
recipient-mlkem-1c8d2e...: <base64 KEM ct>
cipher: aes-256-gcm-siv$iv=<base64 iv>
```

Multi-recipient:
```
recipients: mlkem:1c8d2e...,mlkem:9f3a7b...
recipient-mlkem-1c8d2e...: <base64 KEM ct for recipient 1>
recipient-mlkem-9f3a7b...: <base64 KEM ct for recipient 2>
cipher: aes-256-gcm-siv$iv=<base64 iv>
```

The `pbkdf:` field is absent in this mode. Decryption finds the
recipient entry whose fp matches the caller's privkey, runs
`kem_decapsulate`, recovers the AES key, and decrypts.

Password-based encryption (current) is unchanged: `pbkdf:` field
present, no `recipients:` field.

### CLI surface

`--recipient pub.pem` (repeatable) on `encrypt` and
`encrypt-store`. If both `--recipient` and `-k WORD=PASSWORD` are
supplied, the recipient wins for that WORD (mixed mode is
allowed).

### Decryption

`decrypt` already accepts `-k` for password. New: also accepts
`--key-file priv.pem` (already used by `verify-sig`). When the
Encrypted block has `recipients:`, decrypt derives the AES key
via ML-KEM decapsulation using the privkey whose fp matches.

## Acceptance criteria

- [ ] `encrypt --recipient pub1.pem --recipient pub2.pem` produces a multi-recipient Encrypted block
- [ ] Any matching privkey decrypts successfully
- [ ] Non-matching privkey fails cleanly
- [ ] Password-based encryption round-trip is unchanged
- [ ] Tests cover 1-recipient, 2-recipient, wrong-key, and mixed password+recipient cases

Depends on: TODO.roadmap/30 (ML-KEM, shipped).
