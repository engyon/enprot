# 50 — Contract mode via threshold signing

**Priority**: P2
**Status**: specified (supersedes TODO.finalize/28)

## Problem

Two-party agreements need both parties' signatures to advance. The old
multi-sig approach (N signatures in one CHAIN block) is complex and
weaker than threshold.

## Solution

Use Confium threshold signing (roadmap 20). Both parties' keys are
shares of one threshold group. Signing requires K-of-N:

```sh
# Setup: DKG generates group key (no party sees full key)
confium dkg init --session contract-2of3 --parties 2 --quorum 2 --alg ed25519

# Either party can initiate an anchored operation
enprot encrypt --anchor --signer "confium://contract-2of3" file.ept
# → Confium coordinates FROST with the other party
# → Both must participate for the anchor to be produced

# Verification (by either party or third party)
enprot verify-chain --trust-root <group-pubkey> file.ept
```

## Benefits over multi-sig

- Simpler wire format (one sig, not N)
- Key never assembled (DKG; no cold-boot attack window)
- Resharing (rotate committee without key exposure)
- Verification is standard single-sig check

## Policy enforcement

```toml
[chain]
trust_roots = ["ed25519:<group-fp>"]
required_signers = 1  # one threshold sig = quorum met
```

## Acceptance criteria

- [ ] Threshold-signed anchor verifies with group pubkey
- [ ] Policy file with trust_roots enforces the group
- [ ] Docs: two-party contract walkthrough
