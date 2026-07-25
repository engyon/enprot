# Roadmap — enprot blockchain-in-a-file + threshold + PQ

## Status legend
- **shipped** — implemented, tested, merged
- **specified** — TODO written, ready to implement
- **design** — needs design discussion before spec

## Batch A — Publishing (adopt parsanol-rs practices)

| # | File | Priority | Status |
|---|------|----------|--------|
| 01 | `01-release-plz.md` | P0 | specified |
| 02 | `02-crate-split.md` | P0 | specified |
| 03 | `03-docs-rs-metadata.md` | P1 | specified |
| 04 | `04-ci-msrv-beta.md` | P1 | specified |
| 05 | `05-benchmarks.md` | P2 | specified |
| 06 | `06-examples-directory.md` | P2 | specified |

## Batch B — Provider abstraction (foundation for threshold + PQ)

| # | File | Priority | Status |
|---|------|----------|--------|
| 10 | `10-signer-provider-trait.md` | P0 | specified |
| 11 | `11-kem-provider-trait.md` | P0 | specified |

## Batch C — Threshold crypto (via Confium)

| # | File | Priority | Status |
|---|------|----------|--------|
| 20 | `20-threshold-signing.md` | P1 | specified |
| 21 | `21-threshold-encryption.md` | P1 | specified |
| 22 | `22-confium-integration.md` | P1 | specified |

## Batch D — PQ completion

| # | File | Priority | Status |
|---|------|----------|--------|
| 30 | `30-ml-kem.md` | P1 | specified |
| 31 | `31-composite-pq-classical.md` | P2 | specified |
| 32 | `32-pq-threshold-combination.md` | P2 | specified |

## Batch E — Foundation + distributed

| # | File | Priority | Status |
|---|------|----------|--------|
| 40 | `40-config-file.md` | P1 | specified |
| 41 | `41-json-output.md` | P1 | specified |
| 42 | `42-cas-referenced-default.md` | P1 | specified |
| 43 | `43-merge-driver.md` | P2 | specified |
| 44 | `44-resolve.md` | P2 | specified |
| 45 | `45-git-smudge-clean.md` | P2 | specified |
| 46 | `46-capability-policy.md` | P1 | specified |

## Batch F — Applications

| # | File | Priority | Status |
|---|------|----------|--------|
| 50 | `50-contract-threshold.md` | P2 | specified |
| 51 | `51-source-provenance.md` | P2 | specified |
| 52 | `52-supply-chain-manifest.md` | P2 | specified |

## Sequencing

1. **Publishing (01-06)** first — crates.io publication enables downstream consumption.
2. **Provider traits (10-11)** second — abstraction layer for threshold + PQ.
3. **Threshold (20-22)** third — Confium integration via the provider traits.
4. **PQ (30-32)** fourth — ML-KEM + composites + PQ-threshold.
5. **Foundation (40-46)** in parallel — config, JSON, defaults, merge.
6. **Applications (50-52)** last — compose everything above.

## Shipped (from TODO.finalize, carried forward)

- Stage 0: CAS, 4 transforms, det-AEAD default, subcommand CLI, capability model
- Stage 1: chain anchor DAG, CHAIN parser, --anchor flag, verify-chain, payload recomputation, audit-log mode
- Stage 3: Merkle tree, INCLUDE directive
- Stage 5: snapshot/pin
- PQC Phase 1-2: Ed25519, ML-DSA
- Refactors: DRY separator, eliminate unreachable, typed Directive enum, ParseOps ergonomics
- Features: fingerprint, capabilities, completions, lang presets, verify, list
