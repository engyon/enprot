---
title: "CAS Backends"
layout: ../../../layouts/DocPage.astro
---

enprot's content-addressed storage is pluggable: every blob is named
by its SHA3-256 digest, and the `CasStore` trait abstracts where the
bytes live. The default is a local directory (`-c path`, or `cas/`
when it exists). Two schemes always work:

| Spec | Backend | Use |
|---|---|---|
| *(local path)* | `LocalCas` | default; atomic writes, fsync |
| `memory:` | `MemoryCas` | tests, ephemeral runs |
| `s3://bucket/prefix` | `S3Cas` | shared/durable CAS — **requires the `cas-s3` build feature** |
| `ipfs://host:port` | `IpfsCas` | Kubo-node CAS — **requires the `cas-ipfs` build feature** |
| `rekor:` | — | actionable error; transparency-log layer not yet built |

## S3 backend (`--features cas-s3`)

```sh
cargo install enprot --features cas-s3
enprot encrypt -w SECRET -k SECRET=pw -c s3://my-bucket/cas src/
```

Blobs become object keys `prefix/<sha3-256>`. Every GET is re-hashed
and compared before the bytes are returned — a CAS load verifies
content, whatever the transport did. Saves are idempotent (same
content → same key), `enprot cas list` maps to prefix listing,
`enprot cas gc`/`delete` to object deletes.

Implementation notes:

- **SigV4 signing, credentials, and retries are delegated to the
  [`object_store`](https://docs.rs/object_store) crate** — enprot
  never hand-rolls signing code. The standard AWS chain applies:
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars, shared
  config, instance profile.
- Custom endpoints (MinIO, LocalStack, Cloudflare R2) work via
  `AWS_ENDPOINT_URL` (or `AWS_ENDPOINT_URL_S3`); self-signed/plain
  HTTP endpoints also need `AWS_ALLOW_HTTP=1`.
- TLS is rustls (ring) — no OpenSSL anywhere in the tree.
- The pipeline is synchronous; the backend bridges to object_store's
  async API on a private runtime. CAS operations are per-blob, so
  concurrent transforms (`--jobs`) serialize on the bridge — fine at
  blob granularity.

### Example: MinIO for a team CAS

```sh
docker run -d -p 9000:9000 bitnami/minio:latest
export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:9000 AWS_ALLOW_HTTP=1
curl -X PUT -u minioadmin:minioadmin http://localhost:9000/enprot-cas

enprot encrypt --inline=false -w SECRET -k SECRET=pw \
  -c s3://enprot-cas/cas/ file.ept
```

The `CAS S3 backend (MinIO)` CI job exercises the full round-trip —
save/load/contains/list/delete, hash verification, NotFound mapping —
against a real MinIO container on every PR.

## IPFS backend (`--features cas-ipfs`)

```sh
cargo install enprot --features cas-ipfs
enprot encrypt -w SECRET -k SECRET=pw -c ipfs://localhost:5001 src/
```

Points at a Kubo node's HTTP RPC (default port 5001; TLS endpoints
as `ipfs://https://node.example`). The node owns pinning and
retrieval — no gateway fetches, no swarm dialing by enprot.

The mapping is **table-free**: enprot names blobs by SHA3-256, and
CIDv1 with the raw codec and sha3-256 multihash is a pure encoding
of that same digest — so hash ↔ CID is a pair of local functions.
Blobs are stored via `add` with `hash=sha3-256`, raw leaves, and a
1 MiB chunker — under the chunk size a blob is a **single raw leaf
block**, so the returned CID IS the sha3-256 multihash of the exact
bytes and `cat` unwraps it transparently. Saves pin and verify the
node's returned CID equals ours; loads gate on the pin set (Kubo's
streaming endpoints hang on absent blocks rather than error) then
re-hash and compare; `enprot cas list` enumerates the node's pins
filtered to this namespace. A CID with a different codec or hash
function is rejected, not mapped.

**Size ceiling**: blobs above 1 MiB would chunk into a UnixFS tree
whose root no longer equals the content hash — saves beyond that
fail with an explicit unsupported-op error pointing at the S3
backend for large segments.

The `CAS IPFS backend (Kubo)` CI job runs the full round-trip —
save/idempotency/contains/load/list/delete, NotFound mapping —
against a real Kubo container on every PR.

## Rekor transparency layer (`--features cas-rekor`)

`--casdir rekor://host:port` wraps an inner CAS with a Rekor
transparency log: every `save` stores the blob in the inner backend
AND appends a `hashedrekord` entry, giving the repository
non-repudiation — anyone with the log can see a blob was recorded,
and nobody can silently remove it.

Configuration (env):

- `ENPROT_REKOR_INNER` — inner CAS spec (a path, or `memory:`);
  default `.`.
- `ENPROT_REKOR_SIGNER` — Ed25519 private key (PEM) that signs each
  entry (over the blob's SHA3-256 CAS key).

Wire details: the entry's `data.hash` is SHA-256 of the blob (Rekor's
hashedrekord format mandates SHA-256 — transport encoding, not
enprot's content addressing, which stays SHA3-256). Ed25519
signatures are deterministic, so `verify_inclusion(blob)` rebuilds
the exact entry client-side, retrieves it from the log by value, and
checks the returned inclusion proof's RFC 6962-style Merkle path
folds from the leaf to the returned root.

Works against a self-hosted Rekor or `rekor.sigstore.dev` (never
submit test entries to the public log — run a local instance; the
[Rekor docs](https://docs.sigstore.dev/) cover docker-compose
deployments with Trillian).

No CI leg yet: the MinIO/Kubo pattern needs a multi-container
Trillian deployment; tests are env-gated
(`ENPROT_REKOR_TEST_SPEC`) and run on demand, with the unit suite
covering entry determinism and proof-chain verification.

## Not yet implemented

- Nothing in this list for CAS backends — S3, IPFS, and the Rekor
  transparency layer have all shipped. Future work: a CI leg with a
  self-hosted Rekor once a single-container deployment story lands.
