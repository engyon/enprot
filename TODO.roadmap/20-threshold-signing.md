# 20 — Multi-signer signatures (local-first; Confium is one backend)

**Priority**: P1
**Status**: reframed (was: blocked on Confium)

## Reframe

The original framing depended on Confium for FROST threshold
signing. That conflated two concerns:

1. **Coordination** — how `t` of `n` signers agree to sign. This
   is what Confium provides via its daemon.
2. **Production** — given that agreement, how the signature bytes
   are produced and stored.

(2) doesn't need Confium at all. The local-files flow today
supports `t = n` (every signer signs independently with their own
privkey); `t < n` threshold requires Confium for the coordination
step but produces the same wire format. See also TODO.roadmap/22.

## Local variant (works today after TODO.roadmap/59 lands)

`enprot sign --signer priv1.pem --signer priv2.pem FILE` produces
N detached signatures, stored as a single bundle file. Verify
(`enprot verify-sig --multi`) checks every signature.

The signer set is recorded in the bundle header so consumers can
see who signed without parsing each signature individually. This
is the same model GPG's `--detach-sign --multifile` uses.

## Confium variant (future; same wire format)

`enprot sign --signer confium://session-id FILE` triggers FROST
threshold signing via the Confium daemon. The daemon internally
coordinates `t`-of-`n` signers; from enprot's perspective the
result is a single signature (for threshold) or N signatures (for
all-participants). The wire format is identical to the local
variant.

## URI scheme (Confium)

```
confium://<session-id>?endpoint=<url>&quorum=<k>&alg=<ed25519|mldsa>
```

## Algorithm support

| Algorithm | Local (today) | Threshold (Confium, future) |
|---|---|---|
| Ed25519 | per-signer independent sig | FROST (shipped in confium-tc) |
| ML-DSA | per-signer independent sig | research phase in confium-tc |
| Composite | per-leg independent sig | per-leg threshold (future) |

## Acceptance criteria (local variant)

- [ ] `enprot sign` accepts repeatable `--signer`
- [ ] Each signer's signature is stored with its fingerprint
- [ ] `enprot verify-sig --multi` checks every signature
- [ ] Confium URI continues to error with "not yet implemented"
- [ ] Tests cover 1-signer (backwards compat) and N-signer cases

See TODO.roadmap/59 for the concrete implementation tracker.
