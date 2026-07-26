# 57 — Multi-signer chain anchors (local variant of TODO.roadmap/50)

**Priority**: P1
**Status**: specified

## Problem

Chain anchors today carry a single signer + signature. Contracts
(multi-party agreements) need N signatures on the same anchor.
Without this, the chain DAG can only attest "one party approved"
— never "these N parties jointly approved".

## Solution

Extend the chain anchor wire format to carry a list of signers
and a list of signatures. Single-signer anchors stay
backwards-compatible (emit the existing single fields).

### Wire format

Single-signer (unchanged):
```
signer: ed25519:9f3a7b...
sig: <hex>
```

Multi-signer (new):
```
signers: ed25519:9f3a7b...,ed25519:1c8d2e...
sigs: <hex1>,<hex2>
```

The parser checks: if `signers` is present, multi-sig mode. Else
fall back to single `signer:` / `sig:`. The two modes never
coexist on one anchor.

### Signing flow

Each signer signs the same `signing_bytes` (parents, payload
hash, timestamp, mutations). The anchor collects N `(alg, fp,
sig)` triples and emits them in `signers:` / `sigs:` order.

### CLI surface

`--signer` becomes repeatable on `audit-log` and on `--anchor`.
At least one signer is required. If exactly one, emit legacy
format. If more than one, emit multi-sig format.

### Verify

`verify-chain` requires every signature in the list to validate.
A single bad signature fails the whole anchor. (Future: per-policy
`t`-of-`n` threshold where any `t` valid signatures suffice.)

## Acceptance criteria

- [ ] `audit-log --signer priv1.pem --signer priv2.pem` emits a multi-sig anchor
- [ ] `--anchor --signer priv1.pem --signer priv2.pem` works on every transforming subcommand
- [ ] Verify accepts multi-sig anchors; rejects if any signature fails
- [ ] Single-signer anchors round-trip through the new code path without behaviour change
- [ ] Tests cover 1-signer backwards compat, 2-signer happy path, mixed-alg, and one-bad-sig cases
