# 25 — Capability policy CLI surface

**Priority**: P2
**Status**: specified

## Problem

enprot's capability model exists in `src/cappolicy.rs` — it lets release engineers declare which WORDs a caller may encrypt/decrypt. But it's only configurable via a TOML file passed through `--policy-file`. There's no way to query, edit, or debug the policy from the CLI.

## Goals

- New subcommands:
  - `enprot cap list` — list all WORDs and their required capabilities.
  - `enprot cap check --word SECRET --op encrypt` — does the current policy allow this?
  - `enprot cap why --word SECRET` — show the rule chain that decided the answer.
- JSON output for tooling.
- Attribute-based access control (ABAC) primitives (subject attributes, object attributes, rule evaluation).

## Design

```rust
#[derive(clap::Subcommand)]
pub enum CapSubcmd {
    /// List all WORDs and their required capabilities.
    List { #[arg(long)] policy_file: Option<PathBuf> },
    /// Check whether a specific operation is allowed.
    Check { #[arg(long)] word: String, #[arg(long)] op: OpKind },
    /// Explain the rule chain that decides a check.
    Why { #[arg(long)] word: String, #[arg(long)] op: OpKind },
}
```

Output example (`cap why`):

```
$ enprot cap why --word SECRET --op encrypt
Loading policy from .enprot/policy.toml

Decision: DENY
Rule chain:
  [1] rule default-deny     → DENY   (matches: word=*, op=*)
  [2] rule allow-prod-words  → ALLOW  (matches: word=PROD_*, op=encrypt, attr env=prod)
  [3] override               → DENY   (subject lacks attr env=prod)

Recommended action:
  Grant attribute env=prod to subject, OR add a rule allowing word=SECRET.
```

## Implementation plan

1. Extend `src/cappolicy.rs` to track decision provenance (already partly done).
2. Add `cap` subcommand tree to CLI.
3. Implement `--json` per [11-json-output-modes].
4. Doc: `docs/capabilities.md`.

## Test plan

- [ ] `cap list` matches the loaded TOML policy.
- [ ] `cap check` returns correct exit code for allow/deny.
- [ ] `cap why` rule chain is accurate.

## Out of scope

- Hot-reloading policy from disk (separate perf TODO).
- Distributed capability resolution (Confium's job).
