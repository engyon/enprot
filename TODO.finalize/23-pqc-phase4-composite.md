# PQC Phase 4 — Composite signatures and KEMs

## Why

PQ algorithms alone are not enough — a break in lattice crypto would
expose every signature and ciphertext. The IETF LAMPS drafts and
OpenPGP crypto-refresh mandate PQ+classical composites for
high-assurance use. rnp ships composites as their default.

## Scope

1. New `SigAlgKind::CompositeDilithiumEd25519` (and similar)
2. New `KemAlgKind::CompositeKyberX25519`
3. Composite key format: PEM bundle holding two privkeys; load both
4. Sign: produce two signatures, concatenate with domain-separation
   prefix; verify requires both halves valid
5. Encapsulate: produce two ciphertexts, derive shared key via
   HKDF-SHA3-256 over both shared secrets
6. CLI:
   - `enprot keygen composite-dilithium-ed25519`
   - `enprot keygen composite-kyber-x25519`
7. Chain anchors accept composite algorithms
8. Tests:
   - Round-trip both composite constructions
   - Negative: strip the classical half from a composite sig → fail
   - Negative: replace the PQ half with random → fail

## Open design questions

- Which composite draft to track? IETF `draft-ietf-lamps-pq-composite-sigs`
  has the concrete wire format; OpenPGP `crypto-refresh` is already
  shipped by rnp. Recommendation: **OpenPGP format** for rnp interop.
- Prehash variants for large files? Yes, using SHA3-256.

## Out of scope

- SLH-DSA composites. Too large.
- Threshold / multi-party composites.

## Acceptance criteria

- Both composite constructions round-trip in tests
- Documentation in `docs/pqc.md` explains break-resistance model
- SECURITY.md updated with the hybrid rationale
