# Finalize batch — features and polish

| # | File | Status |
|---|------|--------|
| 01 | `01-shell-completions.md`     | done (PR #87) |
| 02 | `02-language-presets.md`      | done (PR #88) |
| 03 | `03-verify-subcommand.md`     | done (PR #89) |
| 04 | `04-list-subcommand.md`       | done (PR #90) |
| 05 | `05-config-file.md`           | deferred (design) |
| 06 | `06-git-smudge-clean.md`      | deferred (needs #05) |
| 07 | `07-json-output.md`           | deferred (needs serde dep) |
| 08 | `08-contributing-changelog.md`| done (PR #91) |
| 09 | `09-pqc-phase1-ed25519.md`    | do next (foundation) |
| 10 | `10-pqc-phase2-ml-dsa.md`     | follow-on (FIPS 204) |
| 11 | `11-pqc-phase3-ml-kem.md`     | follow-on (FIPS 203) |
| 12 | `12-pqc-phase4-composite.md`  | follow-on (PQ+classical) |
| 13 | `13-version-0.4.0.md`         | do once 09–12 land |

## Sequencing rationale

- 09 before 10/11/12 because composite constructions use Ed25519 /
  X25519 as the classical leg.
- 10 and 11 are independent of each other; either can come first.
- 12 depends on both 09 and 11.
- 13 (release) closes out the batch.
