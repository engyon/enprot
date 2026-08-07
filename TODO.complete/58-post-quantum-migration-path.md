# 58 — Post-quantum migration path

**Priority**: P2
**Status**: specified

## Problem

enprot's PKI surface already includes ML-DSA and ML-KEM code paths
(`SigAlgKind::MlDsa`, `KemAlgKind::MlKem`, composite constructions).
But the **migration path** from classical (Ed25519) to post-quantum
(ML-DSA) is undocumented:

- When should a user start signing with ML-DSA?
- What happens to anchors signed with Ed25519 after migration?
- Can a single file contain both classical and PQ anchors?
- How do verifiers know which algorithm to use for each anchor?

NIST finalised ML-DSA (FIPS 204) in 2024. Real-world adoption
requires a documented transition plan, not just code paths.

## Goals

- A `enprot migrate-keys` command that re-signs existing chain
  anchors with a new algorithm.
- Documents the hybrid period (both classical + PQ anchors
  coexist).
- Verifiers auto-detect each anchor's algorithm from the `signer:`
  extfield — no global "mode" flag.
- A `docs/pq-migration.md` guide with the timeline + checklist.

## Design

### Anchor-level algorithm

Each CHAIN anchor already carries `signer:<alg>:<fp>` in its
extfields. The `alg` field (`ed25519`, `mldsa`,
`composite-ed25519-mldsa`) tells the verifier which algorithm to use.
Migration is therefore **per-anchor**, not per-file.

### Migration command

```
enprot migrate-keys --from ed25519 --to composite-ed25519-mldsa \
                    --old-key old.pem --new-key new.pem \
                    FILE
```

This command:
1. Parses the file.
2. For each CHAIN anchor with `signer:ed25519:<old-fp>`:
   a. Verifies the existing signature against `--old-key`.
   b. Re-signs the anchor's payload with `--new-key`.
   c. Updates the `signer:` extfield.
3. Writes the modified file.

### Hybrid period

During the transition, a file can contain:
- Original anchors signed with Ed25519.
- New anchors signed with composite-ed25519-mldsa.
- Verifiers accept both — each anchor is self-describing.

### Deprecation timeline (from TODO #53)

| Phase | Ed25519 status | Composite status | ML-DSA-only status |
|---|---|---|---|
| Now (0.5.x) | Active | Active | Active |
| 1 year | Active | Active | Active |
| Quantum threat emerges | Deprecated | Active | Active |
| Post-quantum era | Removed | Deprecated | Active |

## Implementation plan

1. Implement `enprot migrate-keys` in `src/cli/migrate_keys.rs`.
2. Verify old signatures before re-signing (security: don't blindly
   overwrite anchors that might be tampered).
3. Document the hybrid period in `docs/pq-migration.md`.
4. Add conformance fixtures with mixed-algorithm anchors.
5. Update threat model (TODO #39) with PQ adversary classification.

## Test plan

- [ ] `migrate-keys` preserves anchor payload hashes.
- [ ] Mixed-algorithm files verify correctly.
- [ ] Old Ed25519-only verifiers reject ML-DSA anchors (graceful
  degradation, not crash).
- [ ] Migration is reversible (re-sign with old key restores original).

## Out of scope

- Quantum-safe symmetric encryption (AES-256 is already PQ-safe).
- PQC algorithm selection policy (covered by #53 algorithm deprecation).
- A migration wizard (GUI or interactive); `migrate-keys` is CLI-only.
