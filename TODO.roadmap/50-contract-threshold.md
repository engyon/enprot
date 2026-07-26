# 50 — Contract threshold (multi-signer chain anchors; local-first)

**Priority**: P1
**Status**: reframed (was: blocked on Confium)

## Reframe

A "contract" anchor carries multiple signatures — the file
attestation requires N signers' agreement to be valid. The
local-files flow supports `t = n` today (every signer signs in
turn); `t < n` requires Confium for the coordination step but
produces the same wire format.

## Local variant (works today after TODO.roadmap/57 lands)

`enprot audit-log --signer priv1.pem --signer priv2.pem FILE`
appends each new chain anchor with signatures from every signer.
The anchor's wire format gains two fields:

- `signers: <alg1>:<fp1>,<alg2>:<fp2>,...` (comma-separated)
- `sigs: <hex1>,<hex2>,...` (same order)

Verify walks each pair and checks every signature against the
payload hash. The single-signer format (current) is preserved
backwards-compatibly: when only one signer is supplied, the
existing `signer:` / `sig:` fields are emitted.

## Confium variant (future; same wire format)

`--signer confium://session-id` triggers FROST threshold signing
via the daemon. The result is a single signature (for threshold)
or N signatures (for all-participants); the wire format is
identical.

## Policy enforcement

```toml
[chain]
trust_roots = ["ed25519:9f3a7b...", "ed25519:1c8d2e..."]
required_signers = 2  # both must sign (local variant)
```

For the Confium variant, the policy lists the group pubkey and
`required_signers = 1` (one threshold sig = quorum met).

## Acceptance criteria (local variant)

- [ ] `enprot audit-log` and `--anchor` accept repeatable `--signer`
- [ ] Chain anchors carry multi-sig fields when N > 1
- [ ] Single-signer anchors emit the legacy single-sig fields (backwards compat)
- [ ] `verify-chain` requires every signature to validate
- [ ] Tests cover 1-signer, 2-signer, and mixed-algorithm cases

See TODO.roadmap/57 for the concrete implementation tracker.
