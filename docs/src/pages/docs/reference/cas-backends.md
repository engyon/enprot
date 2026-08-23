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
| `ipfs://…`, `rekor:` | — | actionable error; not yet implemented |

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

## Not yet implemented

- `ipfs://` — planned as plain HTTP against a Kubo RPC (`/api/v0`),
  storing blobs under their SHA3-256 multihash CID.
- `rekor://` — modeled as a transparency-log *layer* wrapping another
  backend (write-through to Rekor, read from the inner store), not a
  primary CAS; see TODO.complete/27.
