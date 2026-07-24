# PQC Phase 2 — ML-DSA-65 signatures

## Why

NIST FIPS 204 ML-DSA-65 is the post-quantum signature algorithm.
Adding it alongside Ed25519 gives enprot PQ-safe signatures today
and unlocks composite constructions (TODO 23).

## Scope

1. Extend `src/pki.rs::SigAlgKind`:
   ```rust
   pub enum SigAlgKind {
       Ed25519,
       MlDsa65,
       MlDsa87,  // Level 5 variant; optional, lower priority
   }
   ```
2. Add `ml_dsa` to `ci/botan-modules` (verify the exact module name
   against Botan 3.7.x — names may be `ml_dsa` or `ml-dsa`)
3. `keygen`, `sign`, `verify-sig` accept `mldsa65` / `mldsa87` as
   `--alg` values
4. Chain anchors (TODO 17) accept any `SigAlgKind` in the `signer:`
   field
5. Tests: round-trip + tamper + cross-alg negative (sign with Ed25519,
   verify as ML-DSA-65 → fail)
6. Docs note: ML-DSA signatures are ~2000 bytes vs Ed25519's 64;
   chain anchors grow accordingly

## Open design questions

- Default parameter set: 65 (Level 3, ~2000 B) vs 87 (Level 5, ~3300 B).
  Recommendation: 65 (rnp's default; smaller).
- Whether to support older "Dilithium" Round 3 names for rnp < 0.18
  interop. Recommendation: NO — NIST final is what matters.

## Out of scope

- SLH-DSA (SPHINCS+). Stateful hash, much larger signatures; defer
  until a use case demands it.
- Hedged vs deterministic signing. Botan default is fine.

## Acceptance criteria

- `enprot keygen mldsa65` produces a valid PEM keypair
- Sign + verify round-trip works for ML-DSA-65
- All existing Ed25519 tests still pass
- CI green on all platforms
