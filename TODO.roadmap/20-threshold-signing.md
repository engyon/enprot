# 20 — Threshold signing via Confium

**Priority**: P1
**Status**: specified

## Problem

Today's `--signer priv.pem` loads a single private key. For high-assurance
use cases (root CAs, multi-party contracts), the signing key should never
exist in one place. Threshold signing via FROST (Confium) solves this:
K-of-N parties each hold a share; no single party sees the full key.

## Solution

`ConfiumSigner` implements `SignerProvider` (roadmap 10). When enprot
calls `provider.sign(msg)`, the ConfiumSigner:

1. Sends `msg` to the local Confium daemon (unix socket or TCP)
2. The daemon coordinates FROST with K-of-N remote parties
3. Each party contributes a partial signature
4. Confium combines partials into a valid signature
5. Returns `(SigAlgKind, signature, group_key_fingerprint)` to enprot

Enprot embeds the signature in the CHAIN block as usual. The `signer:`
field contains the group key fingerprint, not any individual party's.
Verifiers (verify-chain) check against the group pubkey — they can't
tell the signature was produced via threshold.

## URI scheme

```
confium://<session-id>?endpoint=<url>&quorum=<k>&alg=<ed25519|mldsa>
```

Example:
```
--signer "confium://root-ca-3of5?endpoint=unix:///var/run/confium.sock&quorum=3&alg=ed25519"
```

## ConfiumSigner implementation

```rust
pub struct ConfiumSigner {
    endpoint: String,
    session_id: String,
    quorum: usize,
    alg: SigAlgKind,
    group_fp: KeyFp,  // cached at construction
}

impl SignerProvider for ConfiumSigner {
    fn sign(&self, msg: &[u8]) -> Result<(SigAlgKind, Vec<u8>, KeyFp)> {
        // FFI call to confium-ruby or direct confium-core cdylib
        // For Rust-native integration: link against confium-core crate
        let sig = confium::tc::threshold_sign(
            &self.endpoint,
            &self.session_id,
            self.quorum,
            msg,
        )?;
        Ok((self.alg, sig, self.group_fp))
    }
}
```

## Algorithm support

| Algorithm | Threshold scheme | Confium status |
|---|---|---|
| Ed25519 | FROST (Schnorr/EdDSA) | shipped in confium-tc |
| ML-DSA | Threshold Module-LWE | research phase in confium-tc |

Ed25519 threshold is the initial target. ML-DSA threshold follows when
confium-tc ships the Module-LWE threshold protocol.

## Contract mode replacement (supersedes TODO.finalize/28)

Threshold signing **replaces** multi-sig for contract mode:

- **Old plan (multi-sig)**: N signatures in one CHAIN block; each party
  signs independently. Wire format: `sig:hex1;hex2;hex3`.
- **New plan (threshold)**: One group signature in the CHAIN block.
  Wire format unchanged from single-party. The quorum is enforced at
  signing time by Confium, not at verification time.

Benefits:
- Simpler wire format (one sig, not N)
- Stronger security (key never assembled in any party's memory)
- DKG: group key generated without any party seeing the full key
- Resharing: rotate committee members without key exposure

## Dependencies

- `confium-core` crate (Rust, cdylib) or `confium-ruby` gem
- Network connectivity between committee members (TCP/QUIC/WS)
- Each party's key share stored in hardware (PKCS#11/TPM) or software

## Acceptance criteria

- [ ] `ConfiumSigner` implements `SignerProvider`
- [ ] `--signer confium://...` URI parsing
- [ ] Chain anchor produced via threshold signs correctly
- [ ] `verify-chain --trust-root <group-pubkey>` accepts the signature
- [ ] Documentation: Confium setup guide for committee members
