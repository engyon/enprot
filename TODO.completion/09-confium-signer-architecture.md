# 09 — ConfiumSigner / ConfiumKemProvider architecture

**Priority**: P0
**Status**: specified (impl blocked on Confium daemon CLI maturation;
see confium/confium#64)

## Problem

`parse_signer_arg` currently rejects `confium://session-id` URIs.
The provider traits exist but no Confium-backed impl lands. The
threshold primitives (`confium-tc-frost-*`) are working in-process;
the daemon CLI surface for shell-out isn't shipped yet.

This TODO specifies the architecture so implementation can land
quickly when the daemon is ready.

## Integration shape

```
enprot CLI
   │
   ├── parse_signer_arg("confium://session-abc")
   │      ↓
   ├── ConfiumSigner { session_id, daemon_addr }
   │      │  implements AsyncSignerProvider
   │      │
   │      ↓ sign_async(msg)
   │   ┌──────────────────────────────────┐
   │   │  connect to confium daemon        │
   │   │  (TCP/QUIC/WS via confium-net)    │
   │   │                                   │
   │   │  POST sign request {              │
   │   │    session: "session-abc",        │
   │   │    message: <bytes>,              │
   │   │    scheme: "FROST-ed25519"        │
   │   │  }                                │
   │   │                                   │
   │   │  daemon coordinates with N        │
   │   │  parties; returns group signature │
   │   │                                   │
   │   │  ← { signature: <bytes>,          │
   │   │      pubkey_fp: <fp> }            │
   │   └──────────────────────────────────┘
   │      ↓
   └── returns (SigAlgKind::Ed25519, sig, fp)
```

## ConfiumSigner

```rust
pub struct ConfiumSigner {
    session_id: String,
    daemon_endpoint: DaemonEndpoint,  // TCP/QUIC/WS
    scheme: ThresholdScheme,           // FROST-ed25519, FROST-ml-dsa-65, etc.
    cache: RwLock<Option<KeyFp>>,      // group pubkey fingerprint
}

#[async_trait::async_trait]
impl AsyncSignerProvider for ConfiumSigner {
    async fn sign_async(&self, msg: &[u8])
        -> Result<(SigAlgKind, Vec<u8>, KeyFp)>
    {
        let conn = self.daemon_endpoint.connect().await?;
        let req = SignRequest {
            session: self.session_id.clone(),
            message: msg.to_vec(),
            scheme: self.scheme.clone(),
        };
        let resp: SignResponse = conn.call("sign", req).await?;
        let fp = self.cached_fingerprint(&resp.group_pubkey).await?;
        Ok((self.scheme.into(), resp.signature, fp))
    }

    fn fingerprint(&self) -> Result<KeyFp> {
        // Group pubkey fingerprint, derived once per session and cached.
        // Caller uses it to anchor trust roots.
        ...
    }
}
```

## DaemonEndpoint

Abstract over transport. Confium ships three transports
(`confium-net-{tcp,quic,ws}`); enprot picks the right one based on
the URI scheme:

- `confium://session-id` — default (TCP)
- `confium+quic://session-id` — QUIC
- `confium+ws://session-id` — WebSocket

```rust
pub enum DaemonEndpoint {
    Tcp(SocketAddr),
    Quic(SocketAddr),
    Ws(Url),
}
```

## Error semantics

- **Daemon down** → `Error::ProviderUnavailable { backend: "confium", cause }`
- **Timeout** → `Error::ProviderTimeout { deadline_exceeded }`
- **Quorum not reached** → `Error::ThresholdNotMet { required, got }`
- **Session unknown** → `Error::BadSession { session_id }`

All are `Error` variants (typed), not strings. CLI surfaces
user-actionable messages.

## Session lifecycle

A Confium session represents a stable group of N parties with
threshold T. Sessions outlive individual `sign()` calls. enprot:

1. **Doesn't manage session creation** — that's a Confium daemon
   operator concern. enprot assumes the session exists.
2. **Caches the group pubkey** after first lookup, since deriving
   it requires a daemon round-trip.
3. **Reuses connections** across sign calls (connection pool inside
   `DaemonEndpoint`).

## Wire format implications

The chain anchor `signer:` extfield today: `signer:ed25519:<fp>`.

For Confium-backed anchors, extend to express threshold metadata:

```
signer:frost-ed25519:group=<group-fp>;threshold=3;parties=5
```

Verifiers without Confium just check the group pubkey fingerprint
against their trust root — they don't need to know it was threshold.
Verifiers with Confium access can additionally verify the threshold
quorum was met (by querying the daemon's session log).

## KemProvider variant

Symmetric: `ConfiumKemProvider: AsyncKemProvider` for threshold
ML-KEM decapsulation. Same DaemonEndpoint, different RPC.

## Acceptance criteria

- [ ] `ConfiumSigner` implements `AsyncSignerProvider`
- [ ] `ConfiumKemProvider` implements `AsyncKemProvider`
- [ ] `confium://session-id` URI parsing routes through ConfiumSigner
- [ ] Daemon-down, timeout, quorum-not-met errors are typed
- [ ] Connection pool reuses sessions across sign calls
- [ ] Chain anchor wire format extended for threshold metadata
- [ ] Documentation: when to use Confium vs local PEM
- [ ] Cookbooks: 3-of-5 release signing demo

## Blockers

- Confium daemon CLI maturation — [confium/confium#64](https://github.com/confium/confium/issues/64)
- Stable wire protocol for the daemon's sign RPC

## Cross-references

- [[08-async-signer-provider]] — trait this implements
- [[10-capability-threshold-provenance]] — capability model extension
- [[01-strategic-vision]] — why this matters
- TODO.finalize/38 — original Confium tracker
