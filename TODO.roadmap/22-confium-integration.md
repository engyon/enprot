# 22 — Confium integration (one backend, not a blocker)

**Priority**: P2
**Status**: reframed (was: blocked on Confium)

## Reframe

Confium is **one** SignerProvider/KemProvider backend, not a
prerequisite for any feature. The traits were designed (TODOs
10/11) so that local-files flows work today and Confium plugs in
later without touching the trait surface or the wire format.

## Boundary

**Confium owns**: key lifecycle (DKG, storage, resharing),
threshold protocol execution (FROST signing, threshold KEM
decapsulation), network transport between parties.

**Enprot owns**: file format (EPT, CHAIN, Encrypted), capability
model, chain anchors, CAS, Merkle, wire format, verification.

**Integration point**: two trait objects — `SignerProvider` and
`KemProvider`. Enprot calls trait methods; the Confium impl talks
to the Confium daemon behind the trait boundary.

## Local-files (default backend, shipped today)

`--signer /path/to/priv.pem` and (after TODO.roadmap/58)
`--recipient /path/to/pub.pem` are the local-files forms. They go
through `PemSigner` and the local ML-KEM encapsulation path.
**This is the only backend that ships today**, and it covers
every use case that doesn't need cross-host threshold
coordination.

## Confium (future backend; same trait surface)

`--signer confium://session-id` and `--recipient confium://session-id`
route through a future `ConfiumSigner` / `ConfiumKemProvider`
that speaks the daemon's JSON-RPC protocol. The traits they
implement (`SignerProvider`, `KemProvider`) are unchanged from
today; downstream code that consumes the trait objects doesn't
need to know which backend is in use.

### Linking: daemon (recommended)

Enprot talks to a local `confium-daemon` process via unix socket.
No build-time dependency on Confium libraries. The daemon manages
long-lived state (sessions, key shares, party connections) that
doesn't fit enprot's per-file model.

### Protocol (JSON-RPC over unix socket)

```json
// enprot → daemon
{"method": "sign", "params": {"session": "root-ca-3of5", "quorum": 3, "message": "<base64>"}}

// daemon → enprot
{"result": {"signature": "<base64>", "fingerprint": "<hex>", "alg": "ed25519"}}
```

```json
// enprot → daemon
{"method": "decapsulate", "params": {"session": "classified-3of5", "quorum": 3, "ciphertext": "<base64>"}}

// daemon → enprot
{"result": {"shared_secret": "<base64>"}}
```

## URI dispatch (shipped)

`parse_signer_arg(s, alg)` already routes by URI scheme:

- Bare path → `PemSigner` (shipped)
- `confium://...` → `Err("not yet implemented")` (stub for the daemon)
- `pkcs11://...` → `Err("not yet implemented")` (future hardware token)

The stub errors are the right behaviour today: callers see a
clear "this backend isn't wired yet" message rather than a silent
fallback. When the Confium daemon ships, the stub becomes a real
implementation and no consumer code changes.

## DKG and resharing (operational; out of enprot's scope)

Distributed Key Generation and resharing are run via
`confium-cli`, not enprot. Enprot only consumes the resulting
group public key.

```sh
# One-time: generate threshold group key via Confium
confium dkg init --session root-ca-3of5 --parties 5 --quorum 3 --alg ed25519

# Daily: enprot signs via the existing group key
enprot encrypt --anchor --signer "confium://root-ca-3of5" file.ept
```

## Acceptance criteria

- [x] Local-files backend works for all sign/verify/encrypt flows
- [x] `parse_signer_arg` documents the URI scheme
- [x] Confium URIs produce a clear "not yet implemented" error
- [ ] (Future) Confium backend plugs in without touching the SignerProvider trait or any consumer
- [ ] (Future) JSON-RPC protocol spec documented
- [ ] (Future) Daemon-down and timeout error paths
