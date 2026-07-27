# 38 — Confium daemon backend implementation

**Priority**: P2
**Status**: crates released (v0.3.0); daemon integration pending

## Problem

The `confium://` URI scheme is parsed by `parse_signer_arg` but
returns `Err("Confium threshold signing not yet implemented")`.
The trait surfaces (`SignerProvider`, `KemProvider`) are designed
for Confium to plug into, but the actual daemon-communication
implementation is not written.

## Confium crate ecosystem (released 0.3.0)

The Confium project shipped ~45 crates at v0.3.0 in July 2026. The
relevant ones for enprot's integration:

| Crate | Purpose |
|-------|---------|
| `confium` (0.2.0) | Main framework: binary + library entry point. |
| `confium-core` (0.2.0) | Engine: plugin loader, registry, FFI entry points. |
| `confium-api` (0.3.0) | Plugin SDK: `OpaqueHandle`, `OptionMap`, `SignaturePlugin`/`KemPlugin`/`AeadPlugin` traits, error model. |
| `confium-cli` (0.3.0) | CLI binary (`confium` command). **Currently scaffolding** — only `version` is implemented; other commands exit with status 2. |
| `confium-daemon` (0.3.0) | JSON-RPC daemon — the actual threshold-coordination service. |
| `confium-net` (0.3.0) | Network transport abstraction (TCP/QUIC/WebSocket variants under separate crates). |
| `confium-tc` (0.3.0) | Threshold crypto primitives: session state machine, coordinator, reshare, KEM. Real working crypto. |
| `confium-tc-frost-ed25519` (0.3.0) | FROST threshold Ed25519 — produces RFC 8032 signatures verifiable by any conformant verifier. |
| `confium-tc-frost-ml-dsa-65` (0.3.0) | FROST over ML-DSA-65 (FIPS 204). |
| `confium-tc-ml-kem` (0.3.0) | Threshold ML-KEM (FIPS 203) for post-quantum encryption. |
| `confium-pki` (0.3.0) | X.509 cert, scoped delegation, CMS, XMLDSig. |
| `confium-store` (0.3.0) | Compartmentalized key/secret persistence (backends: openpgp-card, pkcs11, tpm, cloud). |

## What exists today in enprot

- `PemSigner` implements `SignerProvider` for local PEM files (in `src/provider.rs`)
- `parse_signer_arg` routes `confium://` URIs to a stub error
- Multi-signer flows work locally via TODO.finalize/19 + 28
- Multi-recipient encryption works locally via TODO.roadmap/58
- OpenPGP signature support landed via rnp-rs (TODO 51 series)

## What Confium provides today

The released crates supply real, working threshold cryptography:
- FROST threshold Ed25519 / ML-DSA / P-256 / ElGamal / BLS
- Threshold ML-KEM (FIPS 203) for post-quantum encryption
- GG18 threshold ECDSA
- CMP20 threshold ECDSA over P-256
- Threshold ECIES over P-256
- Threshold BFV fully homomorphic encryption
- Threshold ring signatures

But the **daemon integration is incomplete**: `confium-cli` is
scaffolding (only `version` works), so there's no `confium sign`
subcommand to shell out to yet.

## Integration plan (when daemon is ready)

The architectural shape stays as designed:

1. **`ConfiumSigner: SignerProvider`** — for `confium://session-id` URIs.
   - Connects to the daemon via `confium-net` (TCP/QUIC/WS) using
     the session ID as the routing key.
   - Sends a sign request; daemon coordinates FROST threshold
     signing with all parties in the session.
   - Returns the group signature (RFC 8032 Ed25519 or PQ
     equivalent — same wire format as local signatures).
2. **`ConfiumKemProvider: KemProvider`** — same pattern for
   threshold KEM decapsulation.
3. **Wire format unchanged** — the anchor's `signer:` extfield and
   the Encrypted block's `recipients:` extfield don't change between
   local and Confium modes. That's the architectural guarantee from
   TODO.roadmap/22.

When `confium-cli sign --session <id> --message <bytes>` ships,
enprot can shell out as the simplest integration path. Going through
`confium-net` directly is the higher-performance path for batched
operations.

## Why this is still "blocked"

The crates are real, but **the daemon end-to-end story isn't
there yet**. enprot could integrate the threshold primitives
(`confium-tc-frost-ed25519`) directly to do single-process
"threshold-style" signing, but that bypasses the multi-party
coordination that's the entire point of Confium.

The user's architectural directive applies: local-first flows
(`PemSigner`, multi-sig bundles, ML-KEM recipients) all work today;
Confium is for the distributed-trust case where multiple parties
need to co-sign.

## Acceptance criteria

- [ ] `ConfiumSigner` implements `SignerProvider`
- [ ] `ConfiumKemProvider` implements `KemProvider`
- [ ] `confium://session-id` URI routes through the daemon (or the
      daemon-equivalent coordinator API once it stabilizes)
- [ ] Daemon-down and timeout paths produce clean errors
- [ ] Documentation: Confium setup guide for committee members
