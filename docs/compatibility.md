# Compatibility matrix

Which enprot version's OUTPUT can be consumed by which enprot
version. Automated by `cross-version.yml` (TODO.complete/60):

- **backwards** — every fixture in `tests/cross-version/v*/`
  (produced by that released binary) decrypts with the current
  build. Breaking this is a release blocker.
- **forward** — the current build's output decrypts with the
  previous released binary. Covers N-1 only, by design.

## Current status

| Produced by | Consumed by | Status | Evidence |
|---|---|---|---|
| 0.5.50 | current | verified | `v0.5.50/` fixtures, CI green |
| 0.5.56 | current | verified | `v0.5.56/` fixtures, CI green |
| current | previous release | verified | `forward-compat` CI job |

Cipher coverage per fixture set: default `aes-256-siv`,
`aes-256-gcm`, `aes-256-gcm-siv-det`, `--compress` (zlib
extfield path), and CAS-referenced `STORED` (with the fixture's
`cas/`).

## Known incompatibilities

- **0.4.x → 0.5.x**: the PBKDF extfield format changed between
  0.4 and 0.5 (found manually, pre-dating this harness). 0.4
  output is NOT decryptable by 0.5+. No fixtures exist (no
  working release binaries pre-0.5.50, see
  `tests/cross-version/README.md`).

## Policy

- A change that breaks backwards compatibility requires a major
  version bump and a migration note here.
- Each release adds its fixtures (`tests/cross-version/
  generate.sh`) so the matrix grows automatically.
