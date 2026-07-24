# Finalize batch — features and polish

| # | File | Stage | Status |
|---|------|-------|--------|
| 01 | `01-shell-completions.md`     | —     | done (PR #87) |
| 02 | `02-language-presets.md`      | —     | done (PR #88) |
| 03 | `03-verify-subcommand.md`     | —     | done (PR #89) |
| 04 | `04-list-subcommand.md`       | —     | done (PR #90) |
| 05 | `05-config-file.md`           | —     | deferred (design) |
| 06 | `06-git-smudge-clean.md`      | —     | deferred (needs #05) |
| 07 | `07-json-output.md`           | —     | deferred (needs serde dep) |
| 08 | `08-contributing-changelog.md`| —     | done (PR #91) |
| 09 | `09-pqc-phase1-ed25519.md`    | PQC   | done (PR #99) |
| 10 | `10-pqc-phase2-ml-dsa.md`     | PQC   | superseded by `21-pqc-phase2-ml-dsa.md` |
| 11 | `11-pqc-phase3-ml-kem.md`     | PQC   | superseded by `22-pqc-phase3-ml-kem.md` |
| 12 | `12-pqc-phase4-composite.md`  | PQC   | superseded by `23-pqc-phase4-composite.md` |
| 13 | `13-version-0.4.0.md`         | —     | done (PR #100, tag `0.4.0`) |
| 14 | `14-capability-model.md`      | Foundation | do first — every later stage depends on it |
| 15 | `15-det-aead-default.md`      | Foundation | small, high-leverage default flip |
| 16 | `16-cas-referenced-default.md`| Foundation | enables merge-friendly encryption |
| 17 | `17-chain-dag.md`             | Stage 1 | blockchain-in-a-file core |
| 18 | `18-verify-chain.md`          | Stage 1 | verifier for chain anchors |
| 19 | `19-merge-driver.md`          | Distributed | lock-free collaboration |
| 20 | `20-resolve.md`               | Distributed | conflict resolver UI |
| 21 | `21-pqc-phase2-ml-dsa.md`     | Stage 2 (PQC) | FIPS 204 signatures |
| 22 | `22-pqc-phase3-ml-kem.md`     | Stage 2 (PQC) | FIPS 203 KEM, multi-recipient |
| 23 | `23-pqc-phase4-composite.md`  | Stage 2 (PQC) | PQ+classical hybrids |
| 24 | `24-merkle-tree.md`           | Stage 3 | per-file Merkle structure |
| 25 | `25-include-directive.md`     | Stage 3 | cross-file DAG |
| 26 | `26-capability-policy.md`     | Stage 4a | capability requirement spec |
| 27 | `27-audit-log-mode.md`        | Stage 5a | append-only signed logs |
| 28 | `28-contract-mode.md`         | Stage 5b | multi-sig chain anchors |
| 29 | `29-source-provenance.md`     | Stage 5c | SLSA-style build provenance |
| 30 | `30-snapshot-pin.md`          | Stage 5d | external verifiability without a node |
| 31 | `31-supply-chain-manifest.md` | Stage 5e | vendor → customer manifest flow |

## Sequencing rationale

- **Foundation** (14–16) before everything else: capability model is
  the vocabulary; det-AEAD-default + CAS-referenced-default are the
  format changes that make the rest merge-friendly.
- **Stage 1** (17–18) before Stage 2: chain anchors exist before PQC
  signing lands; Ed25519 (already shipped) is the initial signer.
- **Distributed** (19–20) is independent of PQC; can land any time
  after the foundation.
- **Stage 2** (21–23) brings PQ signatures and KEM; composites need
  both Ed25519 (09) and ML-DSA (21) as legs.
- **Stage 3** (24–25) deepens the Merkle structure and makes it
  cross-file.
- **Stage 4a** (26) formalizes the capability requirements; depends
  on 14 (capability model) and 17 (chain anchors).
- **Stage 5** applications (27–31) compose everything above. Each can
  land independently once its prerequisites exist.

## Out-of-scope items (intentionally deferred)

- Config file (05): needs design discussion on layered defaults
- Git smudge/clean (06): needs 05
- JSON output (07): needs serde dep + schema stabilization
- Threshold cryptography (cryptography design discussion)
- Reproducible build enforcement (orthogonal concern)
- Blockchain node integration (out of scope; enprot is single-file)
