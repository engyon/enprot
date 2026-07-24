# Issue triage — July 2026

Nine open issues. This doc sets the order, summarises each, calls out what
the recent Botan 3 upgrade already resolved, and points at the per-issue
TODO files for approach/verification.

## Status snapshot

| # | Title | Type | Verdict |
|---|-------|------|---------|
| 50 | `encrypt_decrypt_agent007_stdin_pass` fails on Windows | bug | **Resolved by PR #57.** Remove the `#[cfg(unix)]` gate, leave a comment on the issue. |
| 48 | Static FIPS build | enhancement | Implement (CI). See `48-static-fips-build.md`. |
| 40 | Support usage with code-signing certificates | enhancement | **Defer.** Significant PKI scope; capture for a future initiative. |
| 39 | Deterministic AES-GCM (+AES-GCM-SIV) | enhancement | Implement. See `39-deterministic-aead.md`. |
| 34 | Add Homebrew package for Enprot | enhancement | **Defer (external).** Formula lives in a tap repo, not here. |
| 23 | Improve error handling | enhancement | **Resolved by PR #57.** Comment + close. |
| 22 | Command-style CLI | enhancement | Implement. See `22-subcommand-cli.md`. |
| 19 | KEY cannot contain commas when provided via CLI | bug | Implement. See `19-no-comma-split-for-key.md`. |
| 18 | Improve multi-file processing | enhancement | Implement. See `18-output-directory-mode.md`. |

## Dependency order

```
#23 (resolved, comment+close)
#50 (resolved, remove cfg gate)
    │
    ▼
#19 (drop comma split for -k)
    │
    ▼
#22 (subcommand CLI)  ◀─── depends on #19's -k parsing
    │
    ▼
#18 (output directory mode)  ◀─── same area (post-parse file pairing)
    │
    ▼
#39 (deterministic AEAD)  ◀─── independent of CLI, depends on cipher layer
    │
    ▼
audit-driven refactors (A1..A12)  ◀─── decompose ParseOps, ExtField type, etc.
    │
    ▼
#48 (static FIPS build, CI only)
    │
    ▼
#34 (Homebrew formula, external)
#40 (code-signing certs, deferred)
```

Issues #22, #18, and the audit all touch `lib.rs::app_main` and the
post-parse file loop. Doing #22 first establishes the subcommand shape;
#18 slots into the file-pairing logic that survives the refactor; the
audit-driven decomposition (`A1` ParseOps split, `A2` ExtField type) is
easiest once the CLI is stable.

#39 is independent of the CLI work and could land in parallel, but doing
it after #22 means the new `enprot encrypt --deterministic` flag has a
natural home.

#48 is CI-only; no code change. Schedules last so it can be reviewed
without source-tree noise.

#34 lives in a tap repo (e.g. `riboseinc/homebrew-enprot`); we document
the formula here, the actual PR is external.

#40 needs scope discussion (which cert formats, online vs offline
verification, signature integration with the existing `ENCRYPTED`/`STORED`
model). Capture in `40-code-signing-certs.md` and defer.

## Branching strategy

One branch per work unit, merged to `main` via rebase. Each PR closes the
relevant issue (`Closes #N` in the body) so GitHub links them.

- `issues/close-already-resolved` — #23, #50 (one PR, two issues)
- `issues/key-no-comma-split` — #19
- `issues/subcommand-cli` — #22
- `issues/output-directory-mode` — #18
- `issues/deterministic-aead` — #39
- `issues/static-fips-build` — #48
- `issues/audit-refactors` — A1..A12 (may split further)
- (defer) #34, #40 — no branch, just docs

## What "good specs" means here

Every PR in this triage adds or strengthens tests:

- New CLI surfaces get integration tests in `tests/cli/*` mirroring the
  existing `assert_cmd` style.
- New crypto paths get KATs in the relevant `src/` module's `#[cfg(test)]
  mod tests` block.
- The audit phase adds a property-based round-trip test (`proptest` or
  hand-rolled) so `encrypt ∘ decrypt = id` is checked across a generated
  input space, not just on a few golden files.
- README examples that touch CLI invocations are mirrored as ignored
  doctests so they fail loudly when the CLI changes.

## What this triage explicitly does NOT do

- Vendor Botan via `botan-src`. Local Botan install remains a prerequisite;
  CI builds from source as today.
- Add new policies. `default` and `nist` remain the only two; `fips` is a
  build-time mode of `nist`, not a runtime policy.
- Change the wire format. Existing encrypted documents must still decrypt.
  The `pbkdf:` and `cipher:` extfield shapes stay; #39 adds new cipher
  variant names but doesn't break old blobs.
- Remove the `legacy` PBKDF. It stays for decrypting old blobs; the warning
  added in PR #58 remains the only nudge.
