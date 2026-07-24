# PQC Phase 2 — ML-DSA (Dilithium) signatures

## Goal

Add NIST FIPS 204 ML-DSA-65 (the Level 3 parameter set) as a
post-quantum signature algorithm alongside Ed25519. rnp ships
ML-DSA-65 as their default PQ signature.

## Why

ML-DSA is the NIST-standardized lattice signature. Once FIPS 204 is
final (already published August 2024), this is the production PQ
signature. Adding it now keeps enprot aligned with rnp and ahead of
the curve.

## Scope

1. Add `ml_dsa`, `dilithium`, `pqcrystals`, `sha3` (already present) to
   `ci/botan-modules`. Verify the exact module name against the Botan
   3.7.x `info.py` output — names may be `ml_dsa` or `ml-dsa`.
2. Extend `src/pki.rs`:
   - `AlgKind::Ed25519 | MlDsa65 | MlDsa87`.
   - `fn keygen(kind, rng)` polymorphic.
   - `fn sign(kind, priv_pem, msg, rng)`.
   - `fn verify(kind, pub_pem, msg, sig)`.
3. CLI:
   - `enprot keygen MlDsa65 [...]`
   - `enprot sign --alg MlDsa65 --key priv.pem FILE`
   - `enprot verify-sig --alg MlDsa65 --key pub.pem FILE.sig FILE`
4. Wire format extension: signature file header gets an `Algorithm:`
   line so the verifier can dispatch without guessing.
5. Tests: round-trip + tamper for ML-DSA-65, plus a cross-alg negative
   (sign with Ed25519, verify as ML-DSA-65 → fail).

## Open design questions

- Default parameter set: ML-DSA-65 (Level 3, ~2000 B sig) vs ML-DSA-87
  (Level 5, ~3300 B sig). rnp defaults to 65; we should match.
- Whether to support the older Round 3 "Dilithium" names for
  backward compatibility with rnp < 0.18. Recommendation: NO — NIST
  final is what matters.

## Out of scope

- SLH-DSA (SPHINCS+). Stateful hashes, much larger signatures, only
  useful in niche long-term-archive scenarios. Defer to a future phase
  if a user asks.
- Hedged vs deterministic signing. Botan's default is fine; revisit
  only if a policy requires it.

## Acceptance criteria

- `cargo test` includes ML-DSA round-trip and tamper tests.
- `ci/botan-modules` updated; CI green on Linux + macOS.
- README.adoc "Signatures" section extended with ML-DSA usage.
