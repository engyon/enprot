# 23 — CHAIN anchor format spec

**Priority**: P1
**Status**: specified

## Problem

CHAIN blocks are the tamper-evident history layer. Their on-disk format is documented in `docs/schemas/chain-anchor.md` as prose but has no formal verification rules. Different code paths in enprot assume different invariants.

## Goals

- Single document defining:
  - Wire format (extfield names, ordering, encoding).
  - Cryptographic invariants (what's signed, hash algorithm, signature scheme).
  - Verification rules (how a verifier decides PASS / FAIL / INCONCLUSIVE).
  - Identity model (who is the "signer"; how to map identity to a trust policy).
- Test suite that asserts every documented rule.

## Wire format

```
// <( CHAIN anchor )>
// <( index:N )>
// <( prev:HEX32 )>           # SHA3-256 of the previous CHAIN block's canonical bytes
// <( file_hash:HEX32 )>      # SHA3-256 of the file's canonical-bytes at this revision
// <( integrated_time:UNIXTS )>
// <( sig kind=K name=N sig=BASE64 [cert=PEM] [rekor=URL] )>
// <( END anchor )>
```

K ∈ { `pem-pgp`, `pem-ed25519`, `pem-ml-dsa`, `composite-ed25519-ml-dsa`, `sigstore-keyless` }.

### Canonical bytes

`canonical_bytes(file)` = the file's text content with all CHAIN blocks stripped, then UTF-8 normalized (NFC), then CRLF → LF.

### Signing payload

`signing_payload(anchor)` = `index || prev || file_hash || integrated_time`, all as big-endian fixed-width fields. Hashing this payload with SHA3-256 yields the digest that's signed.

### Verification rules

1. Parse the extfields; reject if required fields missing.
2. Recompute `file_hash` from `canonical_bytes(file)`; reject on mismatch.
3. Recompute the signing payload; hash it; verify signature against the signer's public key (or Fulcio cert for `sigstore-keyless`).
4. For `sigstore-keyless`: fetch the Rekor entry, verify inclusion proof, validate the cert chain to Fulcio root, check the OIDC `sub` matches the configured identity policy.
5. Walk the chain: anchor N's `prev` must equal SHA3-256 of anchor N-1's canonical bytes. Gap = tamper-evident break.

## Implementation plan

1. Write `docs/schemas/chain-anchor-v1.md`.
2. Add `tests/chain_anchor_spec.rs` covering each rule.
3. Document the identity model + trust policy (allow-lists, regex, threshold).
4. Reference this spec from [03-sigstore-keyless-signing].

## Test plan

- [ ] Every "rule N" in the spec has a positive + negative test.
- [ ] Existing chain-anchor handling in `src/ledger/` passes the new tests.
- [ ] Spec reviewed by Ribose crypto team.

## Out of scope

- Multi-signer threshold (covered by Confium).
- Pluggable canonicalization schemes (single scheme for now).
