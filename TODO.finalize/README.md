# Finalize batch — features and polish

| # | File | Stage | Status |
|---|------|-------|--------|
| 01 | `01-shell-completions.md`     | —     | done (PR #87) |
| 02 | `02-language-presets.md`      | —     | done (PR #88) |
| 03 | `03-verify-subcommand.md`     | —     | done (PR #89) |
| 04 | `04-list-subcommand.md`       | —     | done (PR #90) |
| 05 | `05-config-file.md`           | Foundation | specified; layered TOML + `enprot init` |
| 06 | `06-git-smudge-clean.md`      | Foundation | specified; needs 05 + 15 + 16 |
| 07 | `07-json-output.md`           | Foundation | specified; typed schemas per command |
| 08 | `08-contributing-changelog.md`| —     | done (PR #91) |
| 09 | `09-pqc-phase1-ed25519.md`    | PQC   | done (PR #99) |
| 10 | `10-pqc-phase2-ml-dsa.md`     | PQC   | superseded by `21-pqc-phase2-ml-dsa.md` |
| 11 | `11-pqc-phase3-ml-kem.md`     | PQC   | superseded by `22-pqc-phase3-ml-kem.md` |
| 12 | `12-pqc-phase4-composite.md`  | PQC   | superseded by `23-pqc-phase4-composite.md` |
| 13 | `13-version-0.4.0.md`         | —     | done (PR #100, tag `0.4.0`) |
| 14 | `14-capability-model.md`      | Foundation | done (PR #103) |
| 15 | `15-det-aead-default.md`      | Foundation | specified; small default flip |
| 16 | `16-cas-referenced-default.md`| Foundation | specified; enables merge-friendly encryption |
| 17 | `17-chain-dag.md`             | Stage 1 | ledger module done (PR #105); parser + CLI integration pending |
| 18 | `18-verify-chain.md`          | Stage 1 | specified; depends on parser integration of 17 |
| 19 | `19-merge-driver.md`          | Distributed | specified; lock-free git workflows |
| 20 | `20-resolve.md`               | Distributed | specified; conflict resolver UI |
| 21 | `21-pqc-phase2-ml-dsa.md`     | Stage 2 (PQC) | specified; FIPS 204 signatures |
| 22 | `22-pqc-phase3-ml-kem.md`     | Stage 2 (PQC) | specified; FIPS 203 KEM, multi-recipient |
| 23 | `23-pqc-phase4-composite.md`  | Stage 2 (PQC) | specified; PQ+classical hybrids |
| 24 | `24-merkle-tree.md`           | Stage 3 | specified; per-file Merkle structure |
| 25 | `25-include-directive.md`     | Stage 3 | specified; cross-file DAG |
| 26 | `26-capability-policy.md`     | Stage 4a | specified; capability requirement spec |
| 27 | `27-audit-log-mode.md`        | Stage 5a | specified; append-only signed logs |
| 28 | `28-contract-mode.md`         | Stage 5b | specified; multi-sig chain anchors |
| 29 | `29-source-provenance.md`     | Stage 5c | specified; SLSA-style build provenance |
| 30 | `30-snapshot-pin.md`          | Stage 5d | specified; external verifiability without a node |
| 31 | `31-supply-chain-manifest.md` | Stage 5e | specified; vendor → customer manifest flow |
| 32 | `32-dry-separator-resolution.md` | Refactor | done (PR #106) |
| 33 | `33-eliminate-unreachable.md` | Refactor | done (PR #107) |
| 34 | `34-typed-directive-names.md` | Refactor | done (PR #108) |
| 35 | `35-parseops-ergonomics.md`   | Refactor | done (PR #109) |

## Sequencing rationale

- **Foundation** (05–07, 14–16): everything else depends on this.
  Capability model (14) is done. Defaults flips (15–16) are small.
  Config + smudge/clean + JSON (05–07) need design alignment first.
- **Stage 1** (17–18): chain anchors exist before PQC signing lands;
  Ed25519 (already shipped) is the initial signer.
- **Distributed** (19–20) is independent of PQC; can land any time
  after the foundation.
- **Stage 2** (21–23): composites need both Ed25519 (09) and ML-DSA
  (21) as legs.
- **Stage 3** (24–25) deepens the Merkle structure and makes it
  cross-file.
- **Stage 4a** (26) formalizes capability requirements; depends on 14
  and 17.
- **Stage 5** applications (27–31) compose everything above.
- **Refactors** (32–35) are independent improvements; land opportunistically.

## Out-of-scope items (intentionally deferred)

- Threshold cryptography (cryptography design discussion)
- Reproducible build enforcement (orthogonal concern)
- Blockchain node integration (out of scope; enprot is single-file)
- OS keychain integration (caller's responsibility per "key distribution is external")
