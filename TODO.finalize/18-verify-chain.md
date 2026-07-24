# `enprot verify-chain` subcommand

## Why

Adding chain anchors (TODO 17) without a verifier is half a feature.
Users need to confirm a file's history is intact before trusting its
contents.

## Scope

1. New subcommand `verify-chain`:
   - `enprot verify-chain [--trust-root <key-fp>]... [--strict-timestamps] FILE...`
   - Default: walk DAG, verify signatures, report OK/FAIL per file
   - `--trust-root`: only accept anchors signed by listed key
     fingerprints (whitelist). Repeatable.
   - `--strict-timestamps`: require monotonic timestamps across edges
2. Exit non-zero on any failure (CI-friendly)
3. `--json` output mode: machine-readable report
4. Fork reporting: when the DAG has multiple heads, report each path
5. Tests: clean file OK; tampered payload FAIL; tampered signature
   FAIL; unknown signer FAIL with `--trust-root`; fork OK without
   `--strict-timestamps`

## Out of scope

- Auto-resolution of forks (caller decides; merge driver handles)
- Anchor deletion / pruning (governance policy, not enprot)
- Anchor replay protection across files (would require a global
  anchor registry — out of scope)

## Acceptance criteria

- All Stage 1 chain tests pass under `verify-chain`
- `--json` schema documented in `docs/`
- CI uses `verify-chain` as a check on example files
