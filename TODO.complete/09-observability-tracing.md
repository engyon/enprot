# 09 — Observability via `tracing`

**Priority**: P2
**Status**: specified

## Problem

`eprintln!("Reading {}", path)` is the only observability surface, gated by `paops.io.verbose`. It's:

- Unstructured — no span context, no key/value pairs.
- Not routable to OTLP, Jaeger, file, journald.
- Not correlate-able across files (no trace ID).

## Goals

- `tracing` spans on every operation: `parse`, `transform`, `write`, `pbkdf_derive`, `cas_save`, `cas_load`, `sign`, `verify`.
- `-v` enables INFO, `-vv` DEBUG, `-vvv` TRACE.
- Optional OTLP export via `--otlp-endpoint=URL`.
- Existing `eprintln!` calls migrate to `tracing::info!`/`debug!`.

## Design

```rust
#[tracing::instrument(skip(paops))]
fn process_one_file(path_in: &str, path_out: &str, paops: &mut ParseOps) -> Result<()> { /* … */ }
```

Init in `app_main`:

```rust
let sub = tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env());
if let Some(url) = common.otlp_endpoint.as_deref() {
    sub.with(tracing_opentelemetry::layer().with_exporter(opentelemetry_otlp::ExporterConfig { url, .. })).init();
} else { sub.init(); }
```

## Implementation plan

1. Add `tracing` + `tracing-subscriber` to dev-deps (runtime dep `tracing` only).
2. Add `#[instrument]` to public functions.
3. Replace `eprintln!` with structured spans.
4. Wire CLI flags to env filter.
5. Doc: `docs/observability.md`.

## Test plan

- [ ] `RUST_LOG=debug cargo run -- encrypt …` shows spans with paths, durations.
- [ ] OTLP export smoke-tested against local Jaeger.

## Out of scope

- Metrics (Prometheus) — separate TODO if needed.
- Built-in profile dump (use `cargo flamegraph` externally).
