# 38 — OpenTelemetry export

**Priority**: P3
**Status**: specified (continuation of #09 / #31)

## Problem

`tracing` spans are emitted to stderr (or a configured sink). For
single-process debugging this is fine. For production deployments:

- Multi-service pipelines (CI, batch jobs) want **distributed** tracing.
- Operators want **metrics** (counters, histograms), not just spans.
- Aggregation backends (Jaeger, Tempo, Datadog, Honeycomb) ingest
  OTLP, not stderr text.

TODO.complete/31 expands in-process tracing. This TODO takes it
further: export to OTLP so enprot fits into a modern observability stack.

## Goals

- `--otel-endpoint <url>` CLI flag enables OTLP export.
- Spans, metrics, and logs all flow through OTLP.
- No measurable overhead when OTLP is disabled (the default).
- A `docs/observability.md` chapter on production tracing setup.

## Design

### Layered model

```
┌──────────────────────────────────────────────┐
│  enprot code                                 │
│   tracing::info! / debug! / instrument       │
└────────────────┬─────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────┐
│  tracing subscriber layer stack              │
│   ┌─────────────┐ ┌──────────┐ ┌──────────┐ │
│   │ fmt (stderr)│ │ OTLP     │ │ metrics  │ │
│   └─────────────┘ └──────────┘ └──────────┘ │
└────────────────┬─────────────────────────────┘
                 │
   ┌─────────────┼─────────────┐
   ▼             ▼             ▼
stderr       OTLP/gRPC    OTLP/HTTP (metrics)
```

### CLI flags

```
--otel-endpoint <url>      OTLP/gRPC endpoint (e.g. http://localhost:4317)
--otel-service-name <name> Service name in traces (default: "enprot")
--otel-sample-rate <f>     Sampling rate 0.0–1.0 (default: 1.0)
--otel-headers <k=v,...>   Extra headers (e.g. api keys)
```

### Implementation

```rust
// src/cli/mod.rs (or src/observability.rs)
fn init_observability(common: &CommonArgs) -> Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_filter(tracing_subscriber::EnvFilter::from_env("ENPROT_LOG"));

    let otlp_layer = if let Some(endpoint) = &common.otel_endpoint {
        let exporter = opentelemetry_otlp::new_exporter()
            .with_tonic()
            .with_endpoint(endpoint);
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .with_trace_config(/* service name */)
            .install_batch()?;
        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(otlp_layer)
        .init();
    Ok(())
}
```

### Metrics

```rust
// Static counters + histograms
static FILES_PROCESSED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("enprot_files_processed_total", "Files processed").unwrap()
});
static ENCRYPT_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::new("enprot_encrypt_duration_seconds", "Encrypt latency").unwrap()
});
```

Key metrics:

| Metric | Type | Description |
|---|---|---|
| `enprot_files_processed_total` | counter | Files processed (labels: operation) |
| `enprot_bytes_processed_total` | counter | Bytes processed (labels: operation) |
| `enprot_encrypt_duration_seconds` | histogram | Per-block encrypt latency |
| `enprot_cas_operations_total` | counter | CAS ops (labels: op, backend) |
| `enprot_anchor_verifications_total` | counter | Anchor verify attempts (labels: result) |

## Implementation plan

1. Add `opentelemetry`, `opentelemetry-otlp`, `tracing-opentelemetry`
   as optional deps behind a `telemetry` feature.
2. Implement `init_observability` in `src/observability.rs`.
3. Wire `--otel-*` flags into `CommonArgs`.
4. Add the 5 key metrics with appropriate instrumentation points.
5. Document production setup in `docs/observability.md` with a
   docker-compose example (Jaeger + Prometheus + Grafana).

## Test plan

- [ ] With no `--otel-endpoint`, no OTLP code runs (zero overhead).
- [ ] With `--otel-endpoint`, spans appear in a local Jaeger instance.
- [ ] Metrics appear in Prometheus after a 60-second scrape interval.
- [ ] `cargo bench` shows < 1% overhead with telemetry disabled.

## Out of scope

- Correlation IDs propagated via a header/flag (defer until distributed
  use is common).
- Custom dashboards (provided as JSON exports for Grafana).
- APM-style per-line attribution (overhead too high for the value).
