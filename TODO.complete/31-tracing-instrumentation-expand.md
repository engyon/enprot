# 31 — Tracing instrumentation: cover the remaining pipeline

**Priority**: P2
**Status**: specified (continuation of #09)

## Problem

TODO.complete/09 shipped the `tracing` foundation: subscriber setup,
3 instrumented functions (`process_one_file`, `parse`, `transform`).
Production runs now produce structured spans for the parse/transform
hot path. But ~95% of public functions still have no instrumentation.
Gaps:

- **CLI dispatch** — no span for "which subcommand was invoked".
- **Crypto primitives** — `prot::encrypt`, `prot::decrypt`, `pbkdf::derive_key`, `cipher::*` all silent.
- **CAS ops** — `cas::save`, `cas::load` silent. CAS contention is a
  known production issue; without spans we can't see it.
- **Chain verification** — `verify_chain_one_file`, `verify_payload_hashes` silent.
- **PKI** — `pki::sign`, `pki::verify` silent.
- **Ledger** — `AnchorDag::push`, `AnchorDag::verify_signatures` silent.

A typical production trace today shows: `process_one_file{path=X}` →
`parse{fname=X}` → `transform{...}`. Everything inside `transform` —
the actual work — is invisible.

## Goals

- Every public-facing function that does I/O, crypto, or significant
  CPU work has a `#[tracing::instrument]` attribute.
- Spans carry the right level:
  - **TRACE** — inside hot loops (per-block, per-byte).
  - **DEBUG** — per-file, per-operation.
  - **INFO** — per-subcommand invocation.
- A new `ENPROT_LOG` env var maps to a sensible default filter
  (`info,enprot=debug`).
- Documentation: `docs/observability.md` explains how to capture
  traces for production debugging.

## Design

### Instrumentation map

| Module | Function | Level | Fields |
|---|---|---|---|
| `cli::app_main` | `app_main` | INFO | `cmd` (subcommand name) |
| `cli::pipeline::run` | `run` | INFO | `files`, `op`, `jobs` |
| `cli::pipeline::process_one_file` | (already done) | DEBUG | `path_in`, `path_out` |
| `cli::smudge::run` | `run` | INFO | `mode`, `word` |
| `cli::verify::run` | `run` | INFO | `files` |
| `cli::verify_chain::run` | `run` | INFO | `files`, `trust_roots` |
| `cli::list::run` | `run` | INFO | `files` |
| `cli::inspect::run` | `run` | INFO | `file` |
| `cli::provenance_cmd::run_manifest` | `run_manifest` | INFO | `dir` |
| `cli::provenance_cmd::run_attest` | `run_attest` | INFO | `file` |
| `cli::chain_head_cmd::audit_log_stream` | (already done) | INFO | — |
| `etree::parse` | (already done) | DEBUG | `fname` |
| `etree::transform` | (already done) | DEBUG | — |
| `etree::tree_write` | `tree_write` | DEBUG | — |
| `etree::streaming::Parser::next_event` | `next_event` | TRACE | — |
| `cas::save` | `save` | DEBUG | `hash` (after compute), `bytes` |
| `cas::load` | `load` | DEBUG | `hash`, `bytes` |
| `prot::encrypt` | `encrypt` | DEBUG | `alg`, `bytes` |
| `prot::decrypt` | `decrypt` | DEBUG | `alg`, `bytes` |
| `pbkdf::derive_key` | `derive_key` | DEBUG | `alg`, `msec` |
| `cipher::*` | each entry point | TRACE | `alg` |
| `pki::sign` | `sign` | DEBUG | `alg` |
| `pki::verify` | `verify` | DEBUG | `alg`, `ok` |
| `ledger::AnchorDag::push` | `push` | DEBUG | `index`, `parents` |
| `ledger::AnchorDag::verify_signatures` | `verify_signatures` | DEBUG | `count` |
| `ledger::AnchorDag::tips` | `tips` | DEBUG | — |

### `ENPROT_LOG` env var

In `src/cli/mod.rs::app_main`, before any subcommand runs:

```rust
let filter = env::var("ENPROT_LOG").unwrap_or_else(|_| "info,enprot=debug".into());
tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_target(false)
    .init();
```

This matches the `RUST_LOG` convention but is enprot-specific so users
don't need to also set `RUST_LOG=enprot`.

### Don't instrument

- Hot inner loops where the function-call overhead of `#[instrument]`
  would dominate. Per-byte or per-block functions stay un-instrumented;
  per-file or per-operation functions get spans.
- Functions called more than ~1000 times per file (e.g.
  `Parser::next_event` would emit 1000s of TRACE events per file;
  acceptable but only at TRACE level).

## Implementation plan

1. Add `ENPROT_LOG` bootstrap in `app_main`.
2. Instrument `cli::*` dispatch arms (INFO level).
3. Instrument crypto primitives (DEBUG level).
4. Instrument CAS ops (DEBUG level).
5. Instrument ledger ops (DEBUG level).
6. Instrument PKI ops (DEBUG level).
7. Add `docs/observability.md` with usage examples.

## Test plan

- [ ] With `ENPROT_LOG=debug`, a `store` command emits ≥ 5 spans.
- [ ] With `ENPROT_LOG=info,enprot=trace`, a `verify-chain` command
  emits per-anchor spans.
- [ ] With `ENPROT_LOG=` (empty), no trace output.
- [ ] Existing tests still pass (no behavior change).
- [ ] `cargo bench` shows < 1% overhead with `ENPROT_LOG=` (off).

## Out of scope

- OpenTelemetry export — separate TODO once tracing is comprehensive.
- Distributed tracing across multiple enprot invocations (e.g. in CI).
- A `--trace-out <file>` flag — users can already redirect stderr.
