# 21 — Threshold encryption via Confium

**Priority**: P1
**Status**: specified

## Problem

Threshold **signing** protects integrity (who authorized this?).
Threshold **encryption** protects confidentiality (who can read this?).

Use cases unique to threshold encryption:
- **Classified WORD segment**: 3-of-5 clearance holders required to decrypt.
  No single person can read it alone.
- **Dead man's switch**: content sealed to a threshold group; K members
  must agree to unseal.
- **Escrowed secrets**: key rotation without any single party seeing both
  old and new keys.

## Solution

`ConfiumKemProvider` implements `KemProvider` (roadmap 11). When enprot
encrypts a WORD segment with `--recipient-threshold`, the flow is:

### Encrypt side (anyone can encrypt)

1. Enprot calls `provider.encapsulate(rng)`
2. ConfiumKemProvider generates an ephemeral key pair
3. Encapsulates a shared secret against the **group public key**
   (available to anyone — no threshold needed to encrypt)
4. Uses the shared secret as the AES key for WORD encryption
5. Stores the KEM ciphertext in the KEY-RECIPIENTS block

### Decrypt side (K-of-N required)

1. Enprot calls `provider.decapsulate(ciphertext)`
2. ConfiumKemProvider sends the ciphertext to the Confium daemon
3. The daemon coordinates threshold decapsulation:
   - K-of-N parties each compute a partial shared secret
   - Partials combined → full shared secret recovered
   - **No party ever holds the full shared secret alone**
4. Returns the AES key to enprot
5. Enprot decrypts the WORD content

### Wire format

The KEY-RECIPIENTS block stores one threshold entry:

```
// <( KEY-RECIPIENTS )>
// alg=threshold-ml-kem
// group-fp=<group-key-fingerprint-hex>
// ct=<base64-ciphertext>
// quorum=3
// <( END KEY-RECIPIENTS )>
```

### CLI

```sh
# Encrypt to a threshold group (anyone with the group pubkey can encrypt)
enprot encrypt --recipient-threshold "confium://classified-3of5?endpoint=unix:///var/run/confium.sock" \
    -w Classified file.ept

# Decrypt requires K-of-N parties
enprot decrypt --key-provider "confium://classified-3of5?endpoint=unix:///var/run/confium.sock" \
    -w Classified file.ept
```

## Algorithm support

| Algorithm | Threshold scheme | Status |
|---|---|---|
| ML-KEM (FIPS 203) | Threshold Module-LWE KEM | research in confium-tc |
| X25519 | Threshold ECDH | research in confium-tc |
| Composite (ML-KEM + X25519) | Both legs threshold-ized independently | design phase |

## Security properties

- **No single point of failure**: compromise of <K parties doesn't expose content
- **No key assembly**: the shared secret is never in one party's memory
- **Forward secrecy**: ephemeral encapsulation; compromising the group key
  later doesn't decrypt past messages
- **Policy at decrypt time**: the quorum is enforced when decrypting, not
  when encrypting — anyone can encrypt to the group

## Comparison with password-based

| | Password (today) | Single ML-KEM (roadmap 30) | Threshold ML-KEM (this) |
|---|---|---|---|
| Encrypt requires | password | group pubkey | group pubkey |
| Decrypt requires | password | one privkey | K-of-N shares |
| Key distribution | share password | distribute privkey | DKG (no assembly) |
| Compromise threshold | 1 (password leak) | 1 (privkey leak) | K (quorum breach) |

## Acceptance criteria

- [ ] `ConfiumKemProvider` implements `KemProvider`
- [ ] `--recipient-threshold` URI parsing
- [ ] KEY-RECIPIENTS block stores group-fp + ct + quorum
- [ ] Decrypt with threshold produces correct plaintext
- [ ] Decrypt with <K parties fails cleanly
- [ ] Documentation: threshold encryption setup guide
