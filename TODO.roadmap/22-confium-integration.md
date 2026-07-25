# 22 — Confium integration architecture

**Priority**: P1
**Status**: specified

## Boundary

**Confium owns**: key lifecycle (DKG, storage, resharing), threshold
protocol execution (FROST signing, threshold KEM decapsulation), network
transport between parties.

**Enprot owns**: file format (EPT, CHAIN, KEY-RECIPIENTS), capability
model, chain anchors, CAS, Merkle, wire format, verification.

**Integration point**: two trait objects — `SignerProvider` and
`KemProvider`. Enprot calls trait methods; the Confium impl talks to
the Confium daemon behind the trait boundary.

## Linking options

### Option A: cdylib (C ABI)

Link against `libconfium.{so,dylib,dll}` at build time. Add `confium-core`
as an optional dependency:

```toml
[dependencies]
confium-core = { version = "0.1", optional = true }

[features]
threshold = ["confium-core"]
```

```rust
#[cfg(feature = "threshold")]
mod confium_signer {
    use confium_core::tc;
    impl SignerProvider for ConfiumSigner { ... }
}
```

Pros: native Rust → Rust, no daemon process needed.
Cons: enprot binary must be built with confium-core; deploy complexity.

### Option B: daemon (socket)

Enprot talks to a local `confium-daemon` process via unix socket or TCP.
No build-time dependency:

```rust
fn confium_sign(endpoint: &str, session: &str, quorum: usize, msg: &[u8]) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(endpoint)?;
    // Simple JSON-RPC or length-prefixed binary protocol
    stream.write_all(&protocol::sign_request(session, quorum, msg))?;
    let response = protocol::read_response(&mut stream)?;
    Ok(response.signature)
}
```

Pros: enprot doesn't need confium at build time; daemon manages state
(DKG sessions, key shares) that would be awkward to thread through CLI.
Cons: requires a running daemon; extra deployment step.

**Recommendation**: Option B (daemon). Aligns with enprot's "key
distribution is external" principle — Confium is a service, not a
library dependency. The daemon manages long-lived state (sessions,
key shares, party connections) that doesn't fit enprot's per-file model.

## Protocol between enprot and confium-daemon

Minimal JSON-RPC over unix socket:

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

The daemon handles the multi-round FROST/threshold-KEM protocol with
remote parties. Enprot sees only the final result.

## DKG and resharing

DKG (Distributed Key Generation) and resharing are **operational
procedures**, not enprot operations. They're run via `confium-cli`, not
via enprot. Enprot only consumes the resulting group public key.

```sh
# One-time: generate threshold group key via Confium (no enprot involved)
confium dkg init --session root-ca-3of5 --parties 5 --quorum 3 --alg ed25519

# Daily: enprot signs via the existing group key
enprot encrypt --anchor --signer "confium://root-ca-3of5" file.ept

# Annual: reshare (rotate committee) via Confium (no enprot involved)
confium dkg reshare --session root-ca-3of5 --new-quorum 3 --new-parties 5
```

## Acceptance criteria

- [ ] JSON-RPC protocol spec documented
- [ ] `ConfiumSigner` communicates via daemon socket
- [ ] `ConfiumKemProvider` communicates via daemon socket
- [ ] Error handling: daemon down → clean error message
- [ ] Timeout: threshold protocol doesn't complete in N seconds → error
- [ ] Documentation: "Setting up Confium for enprot" guide
