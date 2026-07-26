# 32 — PQ + multi-signer combination (orthogonal; local-first)

**Priority**: P2
**Status**: reframed (was: blocked on Confium)

## Reframe

PQ algorithms (ML-DSA, ML-KEM) and multi-signer coordination are
orthogonal concerns. A composite signature (TODO.roadmap/31)
already signs with multiple algorithms; each leg can
independently be produced by one signer (local) or by N
coordinated signers (Confium). The wire format doesn't care.

## Local variant

A composite Ed25519 + ML-DSA signature with N Ed25519 signers and
M ML-DSA signers is a flat N+M signature set. Each signer signs
the payload independently with their privkey; the wire format
records every `(alg, fp, sig)` triple. Verification requires
every signature to validate.

This is what the local-files flow produces when the caller passes
multiple `--signer` flags pointing at privkeys of different
algorithms. The composite-algorithm abstraction isn't needed —
the multi-signer bundle (TODO.roadmap/59) handles it naturally.

## Confium variant

If the caller wants `t`-of-`n` threshold within one leg (e.g.,
2-of-3 Ed25519 signers must agree), Confium coordinates that
internally and produces a single threshold signature for the leg.
The wire format is identical to a 1-of-1 leg.

## Security analysis

| Attack | Single Ed25519 | Multi-signer Ed25519 (local) | Multi-signer composite (local) | Threshold composite (Confium) |
|---|---|---|---|---|
| Classical key theft | ✗ exposed | ✓ all keys leaked | ✓ all keys leaked | ✓ quorum breach on both legs |
| Quantum adversary | ✗ broken | ✗ broken | ✓ PQ leg survives | ✓ PQ leg survives |
| Threshold breach (K shares) | n/a | n/a (1-of-N leak suffices) | n/a | ✓ only if both quorums breached |

The local composite variant buys PQ survival without daemon
coordination; the threshold variant adds quorum breach resistance
on top.

## Implementation via SignerProvider

The composite is a **meta-provider** that wraps two sub-providers:

```rust
pub struct CompositeSignerProvider {
    pq_leg: Box<dyn SignerProvider>,        // PemSigner or ConfiumSigner
    classical_leg: Box<dyn SignerProvider>, // PemSigner or ConfiumSigner
}
```

The local variant instantiates both legs as `PemSigner`. The
Confium variant instantiates both legs as `ConfiumSigner`. The
trait surface is identical; only the constructor differs.

## Acceptance criteria (local variant)

- [ ] `enprot sign --signer priv-ed25519-1.pem --signer priv-ed25519-2.pem --signer priv-mldsa.pem FILE` produces a 3-signature bundle
- [ ] Each signature carries its algorithm + fingerprint
- [ ] `enprot verify-sig --multi` checks every signature against the algorithm-appropriate verifier
- [ ] Tests cover mixed-algorithm signer sets

Depends on TODO.roadmap/59 (detached multi-sig).
