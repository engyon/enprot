# 21 — Multi-recipient encryption (local-first; Confium is one backend)

**Priority**: P1
**Status**: reframed (was: blocked on Confium)

## Reframe

The original framing depended on Confium for threshold KEM. As
with TODO.roadmap/20, the local-files flow is independent of
Confium's coordination step.

## Local variant (works today after TODO.roadmap/58 lands)

`enprot encrypt --recipient pub1.pem --recipient pub2.pem -w WORD FILE`
encrypts once with a fresh AES-256 key, then encapsulates that
key to each recipient via ML-KEM (already shipped in
TODO.roadmap/30). Any one recipient can decapsulate and recover
the AES key. The wire format records all recipients in the
Encrypted block's extfields so consumers can see the recipient
set.

This is "broadcast encryption" — the standard pattern for
multi-party confidentiality without a coordination daemon. It
does NOT provide `t`-of-`n` decryption (any single recipient
can decrypt). `t`-of-`n` requires Confium for the coordination
step but produces the same wire format.

## Confium variant (future; same wire format)

`enprot encrypt --recipient confium://session-id ...` triggers
threshold KEM via the Confium daemon. The daemon internally
coordinates `t`-of-`n` recipients; from enprot's perspective
the result is the same Encrypted block.

## Security properties

| Variant | Encrypt requires | Decrypt requires | Compromise threshold |
|---|---|---|---|
| Password (today) | password | password | 1 (password leak) |
| Single ML-KEM recipient | recipient pubkey | one privkey | 1 (privkey leak) |
| Multi-recipient ML-KEM (local) | N pubkeys | any 1 privkey | 1 (any recipient's leak) |
| Threshold ML-KEM (Confium) | group pubkey | K-of-N shares | K (quorum breach) |

The local multi-recipient variant trades confidentiality strength
for daemon-free operation. It's the right choice when the threat
model is "any of these trusted parties can read this" rather
than "at least K of these parties must cooperate to read this".

## Acceptance criteria (local variant)

- [ ] `enprot encrypt` accepts repeatable `--recipient`
- [ ] Each recipient gets a per-fp KEM ciphertext in the Encrypted block's extfields
- [ ] Any one matching privkey decrypts successfully
- [ ] Tests cover 1-recipient and N-recipient cases

See TODO.roadmap/58 for the concrete implementation tracker.
