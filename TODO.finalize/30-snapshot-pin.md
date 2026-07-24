# Stage 5d — Snapshot and pin

## Why

For external verifiability without running a node, enprot files need
a "freeze and publish" operation. Pin the chain head hash, publish it
out-of-band (webpage, DNS TXT record, blockchain anchoring service
like Chainpoint), then anyone can verify a file's history against the
published pin.

This is the bridge from "single-file ledger" to "globally verifiable
ledger" without taking on the complexity of a peer-to-peer network.

## Scope

1. `enprot snapshot FILE`:
   - Computes the current chain head hash
   - Outputs `<head-hash> <timestamp> <signer-fp>`
   - Optionally `--publish <url>`: POSTs the snapshot to an anchoring
     service (Chainpoint, OpenTimestamps, private internal service)
2. `enprot pin <expected-hash> FILE`:
   - Verifies that the current chain head matches `expected-hash`
   - Optionally `--fetch <url>`: fetches the expected hash from an
     anchoring service and verifies the timestamp signature
3. `--publish` and `--fetch` use a pluggable interface:
   `src/anchor/service.rs` with a `trait AnchorService` (OCP —
   new services added as new implementations)
4. Built-in service implementations:
   - `file://` — local file (for testing)
   - `print://` — just print the hash (manual publication)
5. Tests: snapshot + pin round-trip; tamper detection; tampered
   publication caught

## Real-life example (docs)

```sh
# Build a release, snapshot it
enprot encrypt --signer release.pem -w ReleaseNotes release.ept
enprot snapshot --publish print:// release.ept > published-hash.txt

# Publish the hash: tweet it, post on website, anchor in Bitcoin via
# OpenTimestamps, etc.

# Customer verifies later
enprot pin $(cat published-hash.txt) --fetch https://corp.example/anchors/ release.ept
```

## Out of scope

- Blockchain node integration (caller runs their own)
- Trust anchor management (caller decides what to trust)
- Timestamp authority client (RFC 3161) — future enhancement

## Acceptance criteria

- Snapshot + pin round-trip works
- Pluggable AnchorService trait; ≥2 implementations
- Docs page with publication workflow
