# 10 — Capability model extension for threshold provenance

**Priority**: P1
**Status**: done (data model); impl blocked on 09

## Problem

The capability model today (`src/capability.rs`) has tiers:
Viewer / Reader / Decryptor(WORD) / Signer(fp) / Verifier(fp).

These express *what* a party can do, not *how* a signature was
produced. A chain anchor signed by 3-of-5 FROST session produces
the same wire bytes as one signed by a single Ed25519 key with the
same group pubkey — verifiers can't tell threshold from single-party.

That's a feature (verifier-agnostic), but the **capability ledger**
needs to record the threshold provenance for audit:

- "This anchor was produced by a 3-of-5 quorum."
- "Parties P1, P2, P4 participated; P3, P5 timed out."
- "Session ID abc123 on daemon confium://cluster-1."

Today this metadata is invisible.

## Solution

Extend the capability model with a `SigningProvenance` enum:

```rust
pub enum SigningProvenance {
    /// Single-party signature from a local PEM key.
    Local {
        pubkey_fp: KeyFp,
        backend: SignerBackend,  // Pem | OpenPGP | Pkcs11
    },
    /// Threshold signature from a Confium session.
    Threshold {
        scheme: ThresholdScheme, // FROST-ed25519 | FROST-ml-dsa-65 | ...
        group_fp: KeyFp,
        threshold: u32,
        parties_total: u32,
        participants: Vec<PartyId>,    // who actually signed
        session_id: String,
        daemon_endpoint: String,
        completed_at: chrono::DateTime<chrono::Utc>,
    },
    /// Hardware-backed single-party signature (TPM/HSM via Confium store).
    HardwareBacked {
        pubkey_fp: KeyFp,
        backend: HardwareBackend,  // Tpm | Hsm | Yubikey | CloudKMS
        device_id: String,
    },
}

pub enum SignerBackend { Pem, OpenPGP, Pkcs11 }
pub enum HardwareBackend { Tpm, Hsm, Yubikey, CloudKMS }
pub enum ThresholdScheme { FrostEd25519, FrostMlDsa65, FrostP256, Bls, Gg18, Cmp20 }
```

## Wire format

The chain anchor `signer:` extfield carries a compact form:

```
# Local PEM:
signer:ed25519:9f3a7b...

# Threshold:
signer:frost-ed25519:group=abc...;t=3;n=5;session=xyz;daemon=tcp://confium:7001

# Hardware-backed:
signer:ed25519:9f3a7b...;backend=tpm;device=/dev/tpm0
```

The capability ledger (off-chain) carries the full `SigningProvenance`
struct, indexed by anchor hash. Verifiers consult the ledger for
audit; the wire format stays compact.

## CapabilitySet extension

```rust
pub struct CapabilitySet {
    tiers: BTreeSet<Capability>,
    /// Per-anchor provenance, keyed by anchor hash.
    /// Populated when capabilities are derived from a parsed file.
    provenance: BTreeMap<AnchorHash, SigningProvenance>,
}
```

`enprot inspect --format json` exposes this; auditors query the JSON
for "show me all threshold-signed anchors in this document".

## ParseOps integration

`ParseOps` carries an `Option<&ConfiumClient>` (None for standalone
use). When set, `verify_chain` populates `provenance` for each
anchor by querying the daemon's session log.

When None (no Confium), only the wire-format `signer:` extfield is
parsed; `Threshold` provenance has empty `participants` and
`session_id`.

## Acceptance criteria

- [x] `SigningProvenance` enum + variants specified
- [ ] Data model added to `src/capability.rs`
- [ ] `signer:` extfield extended for threshold/hardware metadata
- [ ] `CapabilitySet::provenance` field populated by `verify_chain`
- [ ] `enprot inspect --format json` emits provenance
- [ ] Tests: local-PEM, threshold, hardware-backed provenance cases

## Cross-references

- [[08-async-signer-provider]] — produces the threshold metadata
- [[09-confium-signer-architecture]] — daemon queries for participants
- TODO.finalize/14 — original capability model
