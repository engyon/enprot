# 32 — PQ + threshold combination

**Priority**: P2
**Status**: specified

## Problem

Threshold protects against single-party key compromise. PQ protects
against quantum adversaries. Combining them gives the strongest possible
construction: even a quantum computer + threshold breach on one leg
doesn't break the system.

## Solution

Each leg of a composite construction is independently threshold-izable:

### Composite threshold signing

```
CompositeEd25519MlDsa {
    ed25519_leg: Threshold via FROST (K₁-of-N₁)
    mldsa_leg:   Threshold via Module-LWE protocol (K₂-of-N₂)
}
```

Both thresholds must complete for a valid composite signature. The
quorums can differ (e.g., 3-of-5 for Ed25519, 2-of-3 for ML-DSA).

### Composite threshold encryption

```
CompositeX25519MlKem {
    x25519_leg: Threshold ECDH (K₁-of-N₁)
    mlkem_leg:  Threshold Module-LWE KEM (K₂-of-N₂)
}
```

Both legs must threshold-decapsulate. The composite shared key is
HKDF over both legs' threshold-recovered shared secrets.

## Implementation via SignerProvider / KemProvider

The composite is a **meta-provider** that wraps two sub-providers:

```rust
pub struct CompositeSignerProvider {
    pq_leg: Box<dyn SignerProvider>,      // ConfiumSigner (threshold ML-DSA)
    classical_leg: Box<dyn SignerProvider>, // ConfiumSigner (threshold Ed25519)
}

impl SignerProvider for CompositeSignerProvider {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        let (alg1, sig1, fp1) = self.pq_leg.sign(msg)?;
        let (alg2, sig2, fp2) = self.classical_leg.sign(msg)?;
        let composite_sig = format!("{}:{};{}:{}", alg1, hex::encode(sig1), alg2, hex::encode(sig2));
        let composite_fp = composite_fingerprint(&fp1, &fp2);
        Ok((SigAlgKind::CompositeEd25519MlDsa, composite_sig.into_bytes(), composite_fp))
    }
}
```

## Security analysis

| Attack | Single Ed25519 | Threshold Ed25519 | Composite threshold |
|---|---|---|---|
| Classical key theft | ✗ exposed | ✓ needs K shares | ✓ needs K shares on BOTH legs |
| Quantum adversary | ✗ broken | ✗ broken | ✓ PQ leg survives |
| Threshold breach (K shares) | ✗ exposed | ✗ exposed | ✓ other leg's threshold holds |
| Quantum + threshold breach | — | ✗ | ✓ only if BOTH thresholds breached |

## CLI

```sh
# Composite threshold signing
enprot encrypt --anchor \
    --signer "composite://\
        pq=confium://mldsa-3of5?quorum=3&\
        classical=confium://ed25519-2of3?quorum=2" \
    file.ept

# Composite threshold encryption
enprot encrypt \
    --recipient-threshold "composite://\
        pq=confium://mlkem-3of5?quorum=3&\
        classical=confium://x25519-2of3?quorum=2" \
    -w Classified file.ept
```

## Dependencies

- Confium with threshold-ML-DSA support (research phase)
- Confium with threshold-ML-KEM support (research phase)
- Confium with threshold-X25519 (FROST for ECDH — research phase)

These are multi-year research targets in confium-tc. The enprot
architecture is ready for them — the provider traits and composite
construction don't need to change when confium-tc ships new protocols.

## Acceptance criteria

- [ ] `CompositeSignerProvider` wraps two `SignerProvider` impls
- [ ] `CompositeKemProvider` wraps two `KemProvider` impls
- [ ] Sign: both legs produce valid partial sigs → composite valid
- [ ] Verify: either leg tampered → composite fails
- [ ] Tests with mocked Confium (don't require real threshold daemon)
