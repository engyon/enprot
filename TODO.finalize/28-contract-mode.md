# Stage 5b — Contract mode (multi-sig chain anchors)

## Why

Two-party agreements (contracts, MOUs, vendor SLAs) need both
signatures to advance. Today's chain anchors are single-signer.
Contract mode requires N-of-M signatures on each anchor — pure
multi-sig, no key distribution (each party already has their key).

## Scope

1. Chain anchor `signer` field accepts multiple entries:
   ```
   signer: ed25519:9f3a7b...,ed25519:1c8d2e...
   signature: 3045022100...;3045022100...
   ```
2. Policy rule (TODO 26): `[chain] required_signers = 2` plus a
   `trust_roots` list of acceptable keys; verify-chain counts valid
   signatures and rejects if below threshold
3. `--signer` repeatable on `encrypt`/`store`/etc.: collects multiple
   signatures per anchor
4. Workflow doc: two-party contract negotiation example
5. Tests: 2-of-2, 2-of-3, threshold-met, threshold-not-met

## Real-life example (docs)

```sh
# Two parties: law firm and client
enprot keygen ed25519 --out-priv law.pem    --out-pub law.pub
enprot keygen ed25519 --out-priv client.pem --out-pub client.pub

# Law firm drafts, signs their half
enprot encrypt --signer law.pem -w Terms -k Terms=draft contract.ept

# Client signs same anchor (amend-only-the-signature operation)
enprot co-sign --signer client.pem contract.ept

# Either party verifies; both signatures required by policy
cat > .enprot/policy.toml <<EOF
[chain]
trust_roots = ["ed25519:$(enprot fingerprint law.pub)",
               "ed25519:$(enprot fingerprint client.pub)"]
required_signers = 2
EOF

enprot verify-chain --policy-file .enprot/policy.toml contract.ept
```

## Out of scope

- Threshold cryptography (collecting partial sigs and combining) —
  uses N full signatures instead, simpler
- Time-locked contracts (Stage 5c)
- Payment channels (very out of scope)

## Acceptance criteria

- Multiple `--signer` flags produce a multi-sig anchor
- Policy threshold enforced by `verify-chain`
- Two-party contract walkthrough in docs
