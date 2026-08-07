# 39 — Threat model document

**Priority**: P1
**Status**: specified

## Problem

enprot handles secrets (passwords, private keys, ciphertext) but has
no documented threat model. Without one:

- Reviewers can't tell whether a change introduces a security hole.
- Users can't tell which guarantees enprot makes (vs hopes to make).
- Security auditors have nothing to start from.
- We can't reason about priorities for hardening work.

## Goals

- `docs/threat-model.md` captures: assets, adversaries, attack
  surface, in-scope vs out-of-scope guarantees.
- Each guarantee has a test that verifies it (where possible).
- Threat model is reviewed on every release.

## Design

### Document structure

```
docs/threat-model.md

1. Assets
   - Plaintext WORD segments
   - Passwords
   - Private keys
   - CAS blobs (content hashes are public; content may be sensitive)
   - Chain anchor signatures

2. Adversaries
   - Network observer (passive MITM)
   - Disk access (stolen laptop, forensics)
   - Process with same-user privileges
   - Process with root/admin privileges
   - Compiler / build toolchain (supply chain)
   - Cryptographic adversary (algorithmic breakthrough)

3. Attack surface
   - CLI arguments (visible via `ps`)
   - Environment variables (visible via /proc)
   - stdin/stdout pipes
   - CAS directory (file permissions)
   - Config files (.enprot.toml, .enprot/policy.toml)
   - Build dependencies (Botan, rnp-rs, etc.)
   - CI infrastructure (GitHub Actions, secrets in workflow YAML)

4. In-scope guarantees
   - Ciphertext confidentiality (AES-256-SIV / GCM-SIV)
   - Password hardening (PBKDF2 / Argon2 / scrypt at policy-approved cost)
   - Tamper detection (CHAIN anchors + payload hashes)
   - CAS content addressing (SHA3-256)
   - Forward secrecy of ephemeral keyless signing

5. Out-of-scope (non-guarantees)
   - Side-channel resistance of Botan (delegated to Botan)
   - Resistance to root-level adversaries (root can read process memory)
   - Constant-time comparison of passwords (use a real password manager)
   - Protection against compromised build toolchains (use reproducible builds)
   - Quantum-safe encryption (PQC roadmap, not current)

6. Mitigations
   - 0600 perms on private key files (write_key_or_stdout)
   - TTY-aware password prompt (no echo)
   - No plaintext in swap (mlock future TODO)
   - Constant-time PHC comparison where applicable
   - Sigstore transparency log for keyless signatures

7. Open questions
   - Should enprot mlock() crypto buffers to prevent swap leaks?
   - Should we add a --paranoid flag that double-checks everything?
   - What's the canonical way to wipe the in-memory tree after use?
```

### Per-guarantee tests

Each "in-scope guarantee" should map to a test that verifies the
guarantee holds. Example:

| Guarantee | Test |
|---|---|
| AES-256-SIV confidentiality | `proptest_roundtrip.rs` (decrypt fails on tampered ct) |
| PBKDF cost floor | `tests/policy.rs::pbkdf_below_floor_rejected` |
| Chain anchor tamper detection | `tests/cli/issue_15.rs` (modify anchor → verify fails) |
| CAS content addressing | `proptest_invariants.rs::cas_dedup` |

The document links each row to the test file/line.

## Implementation plan

1. Draft the 7 sections (assets, adversaries, surface, guarantees,
   non-guarantees, mitigations, open questions).
2. Cross-link each guarantee to the test that verifies it.
3. Review by a security engineer (Ribose internal).
4. Publish as `docs/threat-model.md` + link from README.
5. Add a CI check that the threat model is mentioned in CHANGELOG
   entries touching crypto/FFI/policy.

## Test plan

- [ ] Each "in-scope guarantee" has a passing test.
- [ ] Threat model is reviewed by ≥1 security engineer.
- [ ] Threat model mentions every dep that touches secrets (Botan, rnp).

## Out of scope

- Formal verification of crypto primitives (delegated to Botan).
- A SOC2 / ISO27001 audit checklist (organisational, not technical).
- Bug bounty programme setup (organisational).
