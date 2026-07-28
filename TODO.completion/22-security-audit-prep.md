# 22 — Independent security audit preparation

**Priority**: P0
**Status**: specified (external audit is multi-month engagement)

## Problem

enprot is crypto-adjacent. Adoption in regulated industries
(healthcare, finance, defense) requires independent security audit.
Existing competitors have them: age, sigstore, sequoia.

Without an audit, the trust ceiling is "small team tool".

## What an audit covers

A third-party firm (NCC Group, Cure53, Trail of Bits, etc.) reviews:

1. **Crypto correctness**: AEAD choices, KDF parameters, key
   derivation, RNG usage, side-channel resistance.
2. **Wire format**: parser robustness against malformed input,
   canonicalization, signature malleability.
3. **Provider abstraction**: PemSigner, future ConfiumSigner —
   boundary integrity, no key material leakage across trait
   boundaries.
4. **CLI surface**: input validation, file permissions on output,
   password handling (TTY vs pipe), secret zeroization.
5. **Build reproducibility**: deterministic output, supply chain
   for Botan/librnp deps.
6. **Threat model**: documented, with audit-tested assertions.

## Preparation: what we can do before hiring auditors

### 1. Threat model document

`docs/security/threat-model.md`:

- Adversary capabilities (passive observer, active MitM, malicious
  collaborator, compromised build infra)
- Assets protected (plaintext content, signature validity,
  audit log integrity)
- Trust boundaries (CLI ↔ library, library ↔ Botan, library ↔
  Confium daemon)
- Assertions: "enprot does not leak plaintext via timing side
  channels" / "enprot CLI zeros password memory on exit"

### 2. Security review checklist

`docs/security/review-checklist.md` — point auditors at:

- `src/cipher.rs` (SymmetricCipher trait, BotanCipher, AesGcmSivCipher)
- `src/prot.rs` (high-level encrypt/decrypt, IV handling)
- `src/pbkdf.rs` (KDF parameter derivation)
- `src/cas.rs` (hash comparison — content-derived, not secret-derived)
- `src/etree/parse.rs` (input parsing)
- `src/provider.rs` (signer abstraction)
- `src/etree/mod.rs::Drop for ParseOps` (zeroization)

### 3. Fuzzing harness

Already tracked in [[13-fuzzing-harness]]. Pre-audit:

- 100+ hours of fuzzing across all targets
- Crash artifacts triaged and fixed
- Corpus checked in for regression

### 4. Reproducible builds

Already tracked in [[12-reproducible-builds]]. Pre-audit:

- All release artifacts reproducible
- Build manifest published per release

### 5. Dependency audit

`cargo audit` + `cargo deny` already in CI. Pre-audit:

- All advisories addressed or risk-accepted
- All licenses compatible with BSD-2-Clause distribution
- No "unmaintained" crate warnings

### 6. Pen-test harness

Test vectors for known-bad inputs:

- Truncated ciphertext
- Tampered authentication tags
- Invalid PHC strings
- Recursive block nesting beyond max-depth
- Path traversal in CAS hash

## Engagement scope

Target: 4-6 week engagement, ~$50-100k.

Output:
- Public report (with redactions for unresolved findings)
- Tracker for findings
- "Audited by X" badge in README once resolved

## Acceptance criteria

- [ ] Threat model document
- [ ] Security review checklist
- [ ] Fuzzing harness (TODO 13) with 100+ hours coverage
- [ ] Reproducible builds (TODO 12) verified
- [ ] All `cargo audit` findings resolved
- [ ] Auditor engaged (RFP issued to 3 firms)
- [ ] Public report published
- [ ] Findings tracker (GitHub Security Advisories)

## Cross-references

- [[12-reproducible-builds]]
- [[13-fuzzing-harness]]
- [[01-strategic-vision]] — security audit is gating for enterprise
