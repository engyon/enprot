# 38 — Confium daemon backend implementation

**Priority**: P2
**Status**: blocked on external system (Confium daemon)

## Problem

The `confium://` URI scheme is parsed by `parse_signer_arg` but
returns `Err("Confium threshold signing not yet implemented")`.
The trait surfaces (`SignerProvider`, `KemProvider`) are designed
for Confium to plug into, but the actual daemon-communication
implementation is not written.

## What exists today

- `PemSigner` implements `SignerProvider` for local PEM files
- `parse_signer_arg` routes `confium://` URIs to a stub error
- Multi-signer flows work locally via TODO.finalize/19 + 28
- Multi-recipient encryption works locally via TODO.roadmap/58

## What Confium needs to provide

- `ConfiumSigner: SignerProvider` — talks to the daemon via
  JSON-RPC over unix socket. Sends the message; daemon
  coordinates FROST threshold signing; returns the group
  signature.
- `ConfiumKemProvider: KemProvider` — same pattern for
  threshold KEM decapsulation.

The wire format (chain anchors, Encrypted blocks) is unchanged
between local and Confium modes — that's the architectural
guarantee from TODO.roadmap/22.

## Acceptance criteria

- [ ] `ConfiumSigner` implements `SignerProvider`
- [ ] `ConfiumKemProvider` implements `KemProvider`
- [ ] `confium://session-id` URI routes through the daemon
- [ ] Daemon-down and timeout paths produce clean errors
- [ ] Documentation: Confium setup guide for committee members
