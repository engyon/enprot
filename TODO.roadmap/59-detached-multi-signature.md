# 59 — Detached multi-signature (local variant of TODO.roadmap/20)

**Priority**: P1
**Status**: specified

## Problem

`enprot sign` produces one detached signature per invocation. A
multi-signer attestation requires N invocations and N output
files — no structured way to bundle them. Consumers can't tell
"these N signatures are over the same payload" without
re-hashing and re-verifying each.

## Solution

`enprot sign` accepts repeatable `--signer` flags. The output is
a single bundle file containing N `(alg, fp, signature)` triples
over the same payload. The bundle format is line-oriented text
(so it diffs cleanly and survives copy-paste):

```
enprot-sig/1
alg: ed25519
fp: 9f3a7b...
sig: <hex>

alg: ed25519
fp: 1c8d2e...
sig: <hex>
```

The `alg:` / `fp:` / `sig:` lines repeat per signer, separated
by a blank line. The header `enprot-sig/1` pins the format
version.

### Verify

`enprot verify-sig --multi --key-file pub1.pem --key-file pub2.pem FILE SIG`
parses the bundle and checks each signature against the
algorithm-appropriate verifier. Every signature must validate.

For backwards compatibility, single-signer output (current
behaviour) is unchanged: passing one `--signer` writes raw
signature bytes, no header. Passing two or more writes the
bundle format.

### Mixed-algorithm signers

`--signer priv-ed25519.pem --signer priv-mldsa.pem` produces a
mixed-algorithm bundle. Each entry carries its own `alg:` field
so verify routes to the right verifier.

## Acceptance criteria

- [ ] `sign --signer priv1 --signer priv2` produces a bundle
- [ ] Single `--signer` produces raw bytes (backwards compat)
- [ ] `verify-sig --multi` parses the bundle and verifies each
- [ ] Mixed-algorithm bundles round-trip
- [ ] Tests cover 1-signer (compat), 2-signer, mixed-alg, and bad-sig cases
