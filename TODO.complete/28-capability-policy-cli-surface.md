# 28 — Capability policy CLI surface

**Priority**: P2
**Status**: specified

## Problem

The capability policy layer (`src/cappolicy.rs`) defines
`CapPolicy` — a TOML file that gates which WORDs a caller may
transform. Today it's only consulted by the encrypt/encrypt-store
path internally. There's no way to:

- Inspect the current policy from the CLI.
- Validate a policy file before passing it to a real command.
- Override individual rules on a single invocation.
- Print the held capability set given a config.

`enprot cap` (#25 / PR #219) exists for capability *introspection*
("what could I do?") but not for capability *policy* ("what am I
allowed to do?"). These are complementary.

## Goals

- `enprot cap policy show` — print the effective policy.
- `enprot cap policy check` — validate a TOML file (parse + lint).
- `enprot cap policy allow --word X --signer Y` —synthesize a one-off
  override at the command line (no file needed).
- Output is human-readable by default, JSON via `--format json`.
- Works on `--global` (`~/.config/enprot/policy.toml`) and
  `--local` (`.enprot/policy.toml`) files interchangeably.

## Design

### Subcommand shape

```
enprot cap policy <SUBcommand>

SUBcommands:
  show     Print the effective policy (defaults + project + global, merged)
  check    Validate a policy file
  allow    Add a temporary allow rule (CLI flag, no file write)
  deny     Add a temporary deny rule (CLI flag, no file write)
  diff     Show the diff between two policy files
```

`show` and `check` are read-only; `allow`/`deny` modify the in-memory
policy for the current process only (no file IO).

### New module: `src/cli/cap_policy.rs`

After #236 lands, all per-subcommand logic lives in `src/cli/<name>.rs`.
This file holds the new `cap policy` dispatch.

```rust
// src/cli/cap_policy.rs
pub fn run(a: CapPolicySubcmd, common: &CommonArgs) -> Result<()> {
    match a.command {
        CapPolicyCommand::Show { source } => show_policy(common, source.as_deref()),
        CapPolicyCommand::Check { path } => check_policy(&path),
        CapPolicyCommand::Allow { word, signer } => {
            // Synthesize a one-off policy rule
        }
        // ...
    }
}
```

### JSON output

The `CapPolicy` struct already derives `serde::Serialize` for tests.
Surface it via the standard `--format json` flag:

```json
{
  "version": 1,
  "trust_roots": [{"id": "signer1", "fingerprint": "abcd..."}],
  "chain": {"require_monotonic_timestamps": true},
  "word_rules": [{"word": "SECRET", "required_capability": "encrypt"}]
}
```

### Validation (lint)

The check command walks the policy and reports:

- Unknown keys (typos).
- Duplicate trust-root IDs.
- WORDs that reference undefined trust roots.
- Cyclic rules (rare but possible in the rule precedence).
- Conflicting `allow` and `deny` rules.

Output is one issue per line, with severity + location:

```
WARN  .enprot/policy.toml:12  trust_root 'signer1' is unused
ERROR .enprot/policy.toml:15  WORD 'SECRET' references undefined trust_root 'missing'
```

## Implementation plan

1. Add the `CapPolicySubcmd` and `CapPolicyCommand` clap types in
   `src/cli/mod.rs` (or wherever the cli struct definitions live
   post-#236).
2. Wire `enprot cap policy` dispatch arm.
3. Create `src/cli/cap_policy.rs` with `run` + helpers.
4. Implement `show` (read + merge + format).
5. Implement `check` (parse + lint, output issues).
6. Implement `allow`/`deny` (synthesize `CapPolicy` overlay).
7. Implement `diff` (structural diff of two `CapPolicy`s).
8. Tests in `tests/cli/cap_policy.rs` for each subcommand.

## Test plan

- [ ] `enprot cap policy show` on a project with no policy prints defaults.
- [ ] `enprot cap policy show --format json` produces stable JSON.
- [ ] `enprot cap policy check valid.toml` exits 0, no output.
- [ ] `enprot cap policy check bad.toml` exits 1, lists issues.
- [ ] `enprot cap policy allow --word X` + encrypt of WORD X succeeds
  where it would otherwise fail the policy.

## Out of scope

- Policy file format versioning beyond the current `version = 1`.
- Per-user policy overrides via OS keychain (separate TODO).
- A `enprot cap policy init` interactive wizard (defer until usage
  patterns crystallize).
