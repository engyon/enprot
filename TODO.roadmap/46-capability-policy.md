# 46 — Capability requirement policy

**Priority**: P1
**Status**: specified (consolidated from TODO.finalize/26)

## Format

```toml
# .enprot/policy.toml
[chain]
trust_roots = ["ed25519:9f3a7b…"]
require_monotonic_timestamps = true

[[word]]
name = "Agent_007"
required_capability = "Decryptor"
accepted_recipients = ["ml-kem:1c8d2e…"]

[[word]]
name = "PUBLIC"
required_capability = "Viewer"
```

## CLI

- `--policy-file <path>` global flag
- `verify-chain --policy-file` applies policy
- `encrypt --policy-file` refuses to write blocks that violate policy
- New `Error::PolicyViolation { rule, context }` variant

## Acceptance criteria

- [ ] All four rule types enforced (trust roots, timestamps, per-WORD
      capability, recipient whitelist)
- [ ] Tests for positive and negative cases
- [ ] `enprot fingerprint` integration for trust_roots population
