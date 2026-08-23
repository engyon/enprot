//! OpenTelemetry export (TODO.complete/38).
//!
//! The crate's spans are emitted through `tracing` throughout
//! (`#[tracing::instrument]` on the crypto/CAS/pipeline layers).
//! This module attaches an OTLP/HTTP exporter to those spans and
//! publishes the `enprot_*` metric family when the caller passes
//! `--otel-endpoint` — and does nothing otherwise.
//!
//! Layering (see the TODO design sketch):
//!
//! ```text
//! enprot code ──► tracing events/spans
//!                    │
//!        registry().with(fmt layer)      → stderr (ENPROT_LOG / -v)
//!                    └─.with(otel layer) → OTLP/HTTP collector
//!                                          + periodic metric export
//! ```
//!
//! Everything heavier than the `tracing` API itself is behind the
//! `telemetry` cargo feature; the CLI flags exist in every build so
//! a user who asks for export gets an actionable rebuild hint
//! instead of a silent no-op (the same convention as the
//! `--features cas-s3` errors for CAS backend specs).
//!
//! The CLI is synchronous and short-lived; export uses OTLP over
//! HTTP with the blocking reqwest client on the SDK's background
//! threads, not a gRPC/tonic stack. [`TelemetryGuard`] flushes on
//! drop so spans reach the collector before process exit.

use std::collections::HashMap;

use crate::error::{Error, Result};

/// OTLP settings parsed from the `--otel-*` CLI flags.
///
/// Derives `Debug` manually via the blanket impl; passwords never
/// appear here — only endpoint metadata.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub endpoint: String,
    pub service_name: String,
    pub sample_rate: f64,
    pub headers: HashMap<String, String>,
}

impl OtelConfig {
    pub fn new(
        endpoint: String,
        service_name: String,
        sample_rate: f64,
        headers: HashMap<String, String>,
    ) -> Result<Self> {
        if !(0.0..=1.0).contains(&sample_rate) {
            return Err(Error::InvalidArg {
                arg: "--otel-sample-rate",
                reason: "must be between 0.0 and 1.0".into(),
            });
        }
        Ok(Self {
            endpoint,
            service_name,
            sample_rate,
            headers,
        })
    }
}

/// Parse `--otel-headers K=V,K2=V2` into a map. Empty segments are
/// skipped so a trailing comma is harmless; a segment without `=`
/// is a hard error — a silently dropped header would send requests
/// to a collector that rejects them for auth.
pub fn parse_otel_headers(spec: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').ok_or_else(|| Error::InvalidArg {
            arg: "--otel-headers",
            reason: format!("malformed header '{pair}', expected k=v"),
        })?;
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            return Err(Error::InvalidArg {
                arg: "--otel-headers",
                reason: "header key is empty".into(),
            });
        }
        if map.insert(k.to_owned(), v.to_owned()).is_some() {
            return Err(Error::InvalidArg {
                arg: "--otel-headers",
                reason: format!("duplicate header '{k}'"),
            });
        }
    }
    Ok(map)
}

/// Normalize a bare collector base URL into a signal path.
///
/// `http://collector:4318` → `http://collector:4318/v1/traces`;
/// an explicit path is preserved (`…:4318/v1/traces` stays).
#[cfg(feature = "telemetry")]
fn signal_url(base: &str, path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") || trimmed.ends_with("/v1/metrics") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}{path}")
    }
}

/// Handle returned by [`init`]; dropping it flushes and shuts the
/// exporters down. Hold it for the lifetime of the process —
/// `app_main` binds it in a local.
#[must_use = "the OTLP exporters only flush on drop of the guard"]
pub struct TelemetryGuard {
    #[cfg(feature = "telemetry")]
    tracer_provider: opentelemetry_sdk::trace::SdkTracerProvider,
    #[cfg(feature = "telemetry")]
    meter_provider: opentelemetry_sdk::metrics::SdkMeterProvider,
}

impl TelemetryGuard {
    /// Force a flush of buffered spans/metrics. Returns exporter
    /// errors (e.g. collector unreachable) without panicking.
    #[cfg(feature = "telemetry")]
    pub fn flush(&self) {
        let _ = self.tracer_provider.force_flush();
        let _ = self.meter_provider.force_flush();
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "telemetry")]
        {
            let _ = self.tracer_provider.shutdown();
            let _ = self.meter_provider.shutdown();
        }
    }
}

/// Install the global tracing subscriber: stderr formatting always,
/// OTLP export when `config` is `Some` and the `telemetry` feature
/// is compiled in. Returns the flush guard when export is live.
///
/// Called after CLI parsing so the `--otel-*` flags are available;
/// `ENPROT_LOG` (falling back to `warn`, `-v` raising to `debug`)
/// still governs the stderr layer.
pub fn init(config: Option<&OtelConfig>) -> Result<Option<TelemetryGuard>> {
    #[cfg(not(feature = "telemetry"))]
    {
        if let Some(cfg) = config {
            return Err(Error::InvalidArg {
                arg: "--otel-endpoint",
                reason: format!(
                    "{} requires a build with the `telemetry` feature \
                     (cargo install enprot --features telemetry)",
                    cfg.endpoint
                ),
            });
        }
        install_fmt_only();
        Ok(None)
    }

    #[cfg(feature = "telemetry")]
    {
        use std::time::Duration;

        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_otlp::WithExportConfig;
        use opentelemetry_otlp::WithHttpConfig;
        use opentelemetry_sdk::Resource;

        let Some(cfg) = config else {
            install_fmt_only();
            return Ok(None);
        };

        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .build();

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(signal_url(&cfg.endpoint, "/v1/traces"))
            .with_headers(cfg.headers.clone())
            .with_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--otel-endpoint",
                reason: format!("trace exporter setup failed: {e}"),
            })?;

        use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .with_resource(resource.clone())
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                cfg.sample_rate,
            ))))
            .build();

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(signal_url(&cfg.endpoint, "/v1/metrics"))
            .with_headers(cfg.headers.clone())
            .with_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--otel-endpoint",
                reason: format!("metric exporter setup failed: {e}"),
            })?;

        use opentelemetry_sdk::metrics::PeriodicReader;
        let reader = PeriodicReader::builder(metric_exporter)
            .with_interval(Duration::from_secs(30))
            .build();

        use opentelemetry_sdk::metrics::SdkMeterProvider;
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(reader)
            .with_resource(resource)
            .build();
        opentelemetry::global::set_meter_provider(meter_provider.clone());

        let otel_layer =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("enprot"));

        use tracing_subscriber::prelude::*;

        let default_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_filter(default_filter),
            )
            .try_init()
            .ok(); // tests may have installed a subscriber already

        Ok(Some(TelemetryGuard {
            tracer_provider,
            meter_provider,
        }))
    }
}

fn install_fmt_only() {
    let default_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(default_filter)
        .with_target(false)
        .try_init()
        .ok(); // don't fail if another subscriber is already set (tests)
}

/// Metric emission points (TODO.complete/38 key metrics).
///
/// One free function per metric — call sites stay a single line,
/// attribute sets live in exactly one place, and with the feature
/// off (or no endpoint given) the calls compile away / hit a no-op
/// provider. Fetching a counter from the global meter each call is
/// an SDK-side cached lookup; these fire at file/block granularity,
/// not per byte.
#[cfg(feature = "telemetry")]
pub mod metrics {
    use opentelemetry::KeyValue;
    use opentelemetry::global;

    fn meter() -> opentelemetry::metrics::Meter {
        global::meter("enprot")
    }

    /// `enprot_files_processed_total{operation}` — one per input
    /// file that went through the pipeline.
    pub fn record_file_processed(operation: &str) {
        meter()
            .u64_counter("enprot_files_processed_total")
            .with_description("Files processed")
            .build()
            .add(1, &[KeyValue::new("operation", operation.to_owned())]);
    }

    /// `enprot_bytes_processed_total{operation}` — plaintext bytes
    /// that flowed through the transform.
    pub fn record_bytes_processed(operation: &str, bytes: u64) {
        meter()
            .u64_counter("enprot_bytes_processed_total")
            .with_description("Bytes processed")
            .build()
            .add(bytes, &[KeyValue::new("operation", operation.to_owned())]);
    }

    /// `enprot_encrypt_duration_seconds` — per-block encrypt
    /// latency histogram.
    pub fn observe_encrypt_duration(duration: std::time::Duration) {
        meter()
            .f64_histogram("enprot_encrypt_duration_seconds")
            .with_description("Per-block encrypt latency")
            .build()
            .record(duration.as_secs_f64(), &[]);
    }

    /// `enprot_cas_operations_total{op, backend}` — CAS layer
    /// activity (save / load / contains / delete).
    pub fn record_cas_operation(op: &str, backend: &str) {
        meter()
            .u64_counter("enprot_cas_operations_total")
            .with_description("CAS operations")
            .build()
            .add(
                1,
                &[
                    KeyValue::new("op", op.to_owned()),
                    KeyValue::new("backend", backend.to_owned()),
                ],
            );
    }

    /// `enprot_anchor_verifications_total{result}` — chain-anchor
    /// verification attempts.
    pub fn record_anchor_verification(result: &str) {
        meter()
            .u64_counter("enprot_anchor_verifications_total")
            .with_description("Anchor verification attempts")
            .build()
            .add(1, &[KeyValue::new("result", result.to_owned())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(endpoint: &str, rate: f64) -> Result<OtelConfig> {
        OtelConfig::new(endpoint.into(), "enprot".into(), rate, HashMap::new())
    }

    #[test]
    fn header_pairs_parse_with_optional_trailing_comma() {
        let h = parse_otel_headers("api-key=secret, x-scope=proj1,").unwrap();
        assert_eq!(h.get("api-key").map(String::as_str), Some("secret"));
        assert_eq!(h.get("x-scope").map(String::as_str), Some("proj1"));
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn header_without_equals_is_rejected() {
        let err = parse_otel_headers("api-key").unwrap_err();
        assert!(
            err.to_string().contains("malformed header 'api-key'"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_and_empty_header_keys_are_rejected() {
        assert!(parse_otel_headers("k=1,k=2").is_err());
        assert!(parse_otel_headers("=v").is_err());
    }

    #[test]
    fn empty_header_spec_yields_empty_map() {
        assert!(parse_otel_headers("").unwrap().is_empty());
    }

    #[test]
    fn sample_rate_is_bounds_checked() {
        assert!(cfg("http://x:4318", 0.0).is_ok());
        assert!(cfg("http://x:4318", 1.0).is_ok());
        for bad in [-0.1, 1.5, f64::NAN] {
            let err = cfg("http://x:4318", bad).unwrap_err();
            assert!(err.to_string().contains("--otel-sample-rate"), "{err}");
        }
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn signal_url_appends_path_only_when_missing() {
        assert_eq!(
            signal_url("http://h:4318", "/v1/traces"),
            "http://h:4318/v1/traces"
        );
        assert_eq!(
            signal_url("http://h:4318/", "/v1/traces"),
            "http://h:4318/v1/traces"
        );
        assert_eq!(
            signal_url("http://h:4318/v1/traces", "/v1/traces"),
            "http://h:4318/v1/traces"
        );
    }

    #[cfg(not(feature = "telemetry"))]
    #[test]
    fn endpoint_without_feature_gives_rebuild_hint() {
        let Err(err) = init(Some(&cfg("http://localhost:4318", 1.0).unwrap())) else {
            panic!("expected rebuild-hint error without the feature");
        };
        let msg = err.to_string();
        assert!(msg.contains("telemetry"), "{msg}");
        assert!(msg.contains("cargo install"), "{msg}");
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn init_without_endpoint_is_fmt_only() {
        // Installing the global subscriber is best-effort (tests run
        // in parallel and another test may own it); both outcomes
        // are fine, we only assert no error and no guard.
        assert!(init(None).unwrap().is_none());
    }
}
