# 31 — Composite PQ + classical signatures and KEMs

**Priority**: P2
**Status**: specified

## Problem

PQ algorithms alone are a bet on lattice crypto. If lattice crypto is
broken, all PQ signatures and ciphertexts are exposed. Composite
constructions (PQ + classical) hedge: a break in either leg doesn't
compromise the system.

## Solution

### Composite signatures

```rust
pub enum SigAlgKind {
    Ed25519,
    MlDsa,
    CompositeEd25519MlDsa,  // new
}
```

A composite signature requires BOTH halves to validate. The wire format
stores two concatenated signatures with a domain-separation prefix:

```
sig: <alg1>:<hex1>;<alg2>:<hex2>
```

`verify-chain` checks both; failure of either → FAIL.

### Composite KEM

```rust
pub enum KemAlgKind {
    MlKem,
    CompositeX25519MlKem,  // new
}
```

The shared key is derived via HKDF over both legs' shared secrets:

```rust
let composite_key = hkdf_sha256(
    &ml_kem_shared,    // PQ leg
    &x25519_shared,    // classical leg
);
```

Both legs must decapsulate correctly for the composite key to match.

### CLI

```sh
# Composite keygen: generates BOTH an Ed25519 and ML-DSA key,
# bundles them into one PEM pair.
enprot keygen composite-ed25519-mldsa --out-priv priv.pem --out-pub pub.pem

# Sign with composite (both halves signed automatically)
enprot sign --alg composite-ed25519-mldsa --key-file priv.pem file.txt

# KEM composite
enprot keygen composite-x25519-mlkem --out-pub pub.pem
enprot encrypt --recipient pub.pem -w Secret file.ept
```

## Botan support

Botan 3.7+ supports both ML-DSA and ML-KEM. X25519 is always available.
The composite construction is assembled in enprot's code, not in Botan —
Botan handles each leg independently; enprot combines them.

## Design constraints

- The composite fingerprint is `SHA3-256(pq_fp || classical_fp)`, not
  either leg's fingerprint alone. This means `verify-chain`'s
  `--trust-root` checks the composite, not individual legs.
- The wire format must distinguish composite from single-alg so verifiers
  know to check both halves.

## Acceptance criteria

- [ ] Composite keygen produces valid dual-algorithm keypair
- [ ] Composite sign produces concatenated signature
- [ ] verify-chain checks both halves; either fails → FAIL
- [ ] Composite KEM: both legs encapsulated; HKDF over both shared secrets
- [ ] Tests: tamper one leg → verification fails
