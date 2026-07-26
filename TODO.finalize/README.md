# Finalize batch — features and polish

All 35 items have been implemented. Items marked "consolidated" were
moved into `TODO.roadmap/` with new numbering; the original spec
files remain here for historical context.

| # | File | Status | Consolidated into |
|---|------|--------|-------------------|
| 01 | `01-shell-completions.md`     | done (PR #87) | — |
| 02 | `02-language-presets.md`      | done (PR #88) | — |
| 03 | `03-verify-subcommand.md`     | done (PR #89) | — |
| 04 | `04-list-subcommand.md`       | done (PR #90) | — |
| 05 | `05-config-file.md`           | done          | TODO.roadmap/40 (PR #133) |
| 06 | `06-git-smudge-clean.md`      | done          | TODO.roadmap/45 (PR #139) |
| 07 | `07-json-output.md`           | done          | TODO.roadmap/41 (PR #130) |
| 08 | `08-contributing-changelog.md`| done (PR #91) | — |
| 09 | `09-pqc-phase1-ed25519.md`    | done (PR #99) | — |
| 10 | `10-pqc-phase2-ml-dsa.md`     | superseded    | `21-pqc-phase2-ml-dsa.md` → TODO.roadmap/31 |
| 11 | `11-pqc-phase3-ml-kem.md`     | superseded    | `22-pqc-phase3-ml-kem.md` → TODO.roadmap/30 |
| 12 | `12-pqc-phase4-composite.md`  | superseded    | `23-pqc-phase4-composite.md` → TODO.roadmap/31 |
| 13 | `13-version-0.4.0.md`         | done (PR #100, tag `0.4.0`) | — |
| 14 | `14-capability-model.md`      | done (PR #103) | — |
| 15 | `15-det-aead-default.md`      | done (PR #119) | — |
| 16 | `16-cas-referenced-default.md`| done          | TODO.roadmap/42 (PR #131) |
| 17 | `17-chain-dag.md`             | done (ledger PR #105 + parser PR #113 + --anchor PR #115) | TODO.roadmap/57 |
| 18 | `18-verify-chain.md`          | done (PR #114) | — |
| 19 | `19-merge-driver.md`          | done          | TODO.roadmap/43 (PR #137) |
| 20 | `20-resolve.md`               | done          | TODO.roadmap/44 (PR #138) |
| 21 | `21-pqc-phase2-ml-dsa.md`     | done (PR #120) | TODO.roadmap/31 (PR #129) |
| 22 | `22-pqc-phase3-ml-kem.md`     | done          | TODO.roadmap/30 |
| 23 | `23-pqc-phase4-composite.md`  | done          | TODO.roadmap/31 (PR #129) |
| 24 | `24-merkle-tree.md`           | done (PR #111) | TODO.roadmap/05 (benches) |
| 25 | `25-include-directive.md`     | done (PR #117) | TODO.roadmap/51-52 (provenance/SCM) |
| 26 | `26-capability-policy.md`     | done          | TODO.roadmap/46 (PR #134) |
| 27 | `27-audit-log-mode.md`        | done (PR #116) | — |
| 28 | `28-contract-mode.md`         | done          | TODO.roadmap/50 (PR #150) + TODO.roadmap/57 |
| 29 | `29-source-provenance.md`     | done          | TODO.roadmap/51 (PR #140) |
| 30 | `30-snapshot-pin.md`          | done (PR #118) | — |
| 31 | `31-supply-chain-manifest.md` | done          | TODO.roadmap/52 (PR #141) |
| 32 | `32-dry-separator-resolution.md` | done (PR #106) | — |
| 33 | `33-eliminate-unreachable.md` | done (PR #107) | — |
| 34 | `34-typed-directive-names.md` | done (PR #108) | — |
| 35 | `35-parseops-ergonomics.md`   | done (PR #109) | — |
