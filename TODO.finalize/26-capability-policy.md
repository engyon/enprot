# Stage 4a — Capability requirement policy

## Why

Today, capability tiers exist (TODO 14) but nothing *requires* them.
A user can sign a chain anchor with any key, decrypt any WORD with
any matching password, no enforcement. For high-assurance use cases
(audit logs, contracts) we need a way to specify "this file's chain
anchors must be signed by one of these keys; these WORDs require
Decryptor capability with one of these key fingerprints; etc."

This is *capability requirement specification*, not key distribution.
The policy file lives alongside the EPT file (or in a `.enprot/`
dir); keys still arrive externally.

## Scope

1. New file format `.enprot/policy.toml`:
   ```toml
   [chain]
   trust_roots = ["ed25519:9f3a7b..."]   # any anchor must be signed by one of these
   require_monotonic_timestamps = true
   
   [[word]]
   name = "Agent_007"
   required_capability = "Decryptor"
   # Optionally: accepted key fingerprints if encryption used KEM
   accepted_recipients = ["ml-kem:1c8d2e..."]
   
   [[word]]
   name = "PUBLIC"
   required_capability = "Viewer"   # no decryption needed
   ```
2. `--policy-file <path>` flag (global): load policy and enforce on
   every operation
3. New error variant `Error::PolicyViolation { rule, context }`
4. `verify-chain --policy-file <path>` applies policy to verification
5. `encrypt --policy-file <path>` refuses to write a block that would
   violate policy
6. Tests: each rule type enforced; missing policy file = open policy

## Out of scope

- Policy distribution (caller's problem — typically committed to git)
- Policy signing (Stage 5 — policy itself could be an EPT file)
- Dynamic policy (run-time rule changes)

## Acceptance criteria

- All four rule types (chain trust roots, monotonic timestamps, word
  capability requirements, recipient whitelist) enforced
- Tests for each rule's positive and negative case
- Docs page with example policy file
