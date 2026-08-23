---
title: "Observability"
layout: ../../../layouts/DocPage.astro
---

enprot is instrumented end-to-end with `tracing` spans (parser, crypto,
CAS, pipeline). By default those spans go to stderr under the `ENPROT_LOG`
filter (`warn` unless set; `-v` implies debug chatter). This page covers
the second consumer: exporting spans and metrics to an OpenTelemetry
collector over OTLP/HTTP, for teams that run Jaeger/Tempo/Zipkin-class
backends or scrape Prometheus.

## Enabling export

Export is a build feature, not a runtime default — the
`opentelemetry`/`reqwest` dependency tree is heavy and most users never
need it:

```sh
cargo install enprot --features telemetry
```

The `--otel-*` flags exist in every build. Passing `--otel-endpoint`
without the feature prints a rebuild hint instead of silently doing
nothing — the same convention as the CAS backend feature errors.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--otel-endpoint URL` | (unset) | OTLP/HTTP base URL, e.g. `http://localhost:4318`. A bare URL gets `/v1/traces` and `/v1/metrics` appended; explicit paths are preserved. |
| `--otel-service-name NAME` | `enprot` | `service.name` resource attribute. |
| `--otel-sample-rate RATE` | `1.0` | Trace sampling (parent-based ratio; `0.0` disables span export). |
| `--otel-headers K=V,...` | (unset) | Extra collector headers, comma-separated — e.g. vendor API keys. |

Example:

```sh
enprot encrypt -w SECRET -k SECRET=hunter2 \
  --otel-endpoint https://otel.example.com:4318 \
  --otel-service-name nightly-batch \
  --otel-sample-rate 0.25 \
  --otel-headers x-scope-site=eu1,api-key=... \
  src/
```

Spans flush when the process exits (the exporters are shut down by a
guard in `app_main`), so short CLI invocations still deliver complete
traces.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `enprot_files_processed_total` | counter | `operation` | Files that completed the transform (`encrypt`, `decrypt`, `store`, `fetch`, `encrypt-store`, `passthrough`). |
| `enprot_bytes_processed_total` | counter | `operation` | Input bytes per file (stdin input records 0). |
| `enprot_encrypt_duration_seconds` | histogram | — | Per-block encrypt latency (KDF + AEAD + compression). |
| `enprot_cas_operations_total` | counter | `op`, `backend` | CAS `save`/`load` through the transform layer; `backend` is the store's `name()` (`local`, `memory`, …). |
| `enprot_anchor_verifications_total` | counter | `result` | `verify-chain` signature checks (`ok` / `failed`). |

Metrics export on a 30-second periodic interval and on process exit.
Batch size is small — a nightly batch run of a few thousand files
produces a few KB of OTLP traffic.

## Local smoke test

The quickest end-to-end check is an all-in-one collector that prints
everything to its own stdout — no storage, no dashboard:

```sh
docker run --rm -p 4318:4318 otel/opentelemetry-collector:latest 2>&1 | grep -E "Traces|Metrics"
```

In another terminal:

```sh
enprot encrypt --inline -w T -k T=pw --otel-endpoint http://localhost:4318 somefile
```

You should see trace and metric export batches logged by the collector.
For a real stack, point the collector at Jaeger (traces) and Prometheus
(metrics); any OTLP-capable backend works unchanged on the enprot side.

## Overhead

- **Feature off** (the default): the instrumentation compiles away
  entirely; there is no OTLP code in the binary.
- **Feature on, no `--otel-endpoint`**: the fmt-to-stderr subscriber is
  installed, exactly as before; no exporter threads exist.
- **Feature on, with endpoint**: spans buffer in-memory and flush from a
  background thread; the encrypt path adds one histogram record per
  block. Metric counters fire per file and per CAS operation, not per
  byte.

## Environment variables

The exporters also honor the standard OTLP environment
(`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_TIMEOUT`, …) as fallbacks for anything not set via
flags; explicit flags win. `service.name` may alternatively come from
`OTEL_SERVICE_NAME` / `OTEL_RESOURCE_ATTRIBUTES` per the SDK defaults.
