# PQC Phase 4 — Composite signatures and KEMs

## Goal

Implement composite PQ + classical algorithms so a break in either
lattice crypto or classical ECC does not compromise the system. This
is what rnp ships as their default PQC mode.

## Why

ML-DSA and ML-KEM alone are not enough — a breakthrough in lattice
cryptanalysis would expose every signature and ciphertext. The
IETF/IETF-spiral and NIST NIST-PQC-composite drafts mandate
PQ+classical composites for high-assurance use cases.

## Scope

1. Composite ML-DSA-65 + Ed25519 signatures:
   - One PEM-encoded bundle holding two privkeys; signing produces two
     signatures concatenated with a domain-separation prefix.
   - Verify requires both halves to validate.
2. Composite ML-KEM-768 + X25519 KEM:
   - Encapsulate produces two ciphertexts; decapsulate yields two
     shared secrets combined via HKDF-SHA3-256.
3. CLI:
   - `enprot keygen Composite-Dilithium-Ed25519`
   - `enprot keygen Composite-Kyber-X25519`
   - The `sign`/`verify-sig`/`encrypt`/`decrypt` commands dispatch on
     the algorithm name in the key's PEM header.
4. Tests:
   - Round-trip both composite constructions.
   - Negative: strip the Ed25519 half from a composite signature →
     verify fails.
   - Negative: replace the X25519 half of a composite KEM ciphertext
     with random → decrypt fails.

## Open design questions

- Which composite draft to track: IETF `draft-ietf-lamps-pq-composite-sigs`
  (concrete wire format) vs OpenPGP `crypto-refresh` sec 5.7 (already
  shipped by rnp). Recommendation: OpenPGP format, since rnp already
  deploys it.
- Whether to support "prehash" variants for large files. Recommendation:
  yes, using SHA3-256 as the prehash, to bound signing time.

## Out of scope

- SLH-DSA composites. Too large; revisit only if a customer asks.
- Threshold / multi-party composites. Out of scope for a CLI tool.

## Acceptance criteria

- `cargo test` includes composite round-trip and negative tests.
- README.adoc "Hybrid PQ+classical" section documents the rationale.
- A SECURITY.md note explaining the break-resistance model.
