# 16 — FFI: typed `EnprotConfig` (replace argv bridge)

**Priority**: P2
**Status**: specified

## Problem

[01-ffi-pipeline-execution] bridges JSON config → argv → `app_main`. This works but has known limits: passwords round-trip through clap parsing (overhead + can leak via /proc on Linux), no way to pass binary secrets, no structured error mapping per operation phase.

## Goals

- A typed `EnprotConfig` struct that the FFI accepts as JSON.
- A new entry point `enprot::run_config(config: EnprotConfig) -> Result<()>` that bypasses clap.
- The CLI also uses `run_config` internally (after its own clap parsing) — single dispatch path.
- JSON schema published at `docs/schemas/config-v1.json`.

## Design

```rust
// src/lib.rs
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
pub struct EnprotConfig {
    pub operation: Operation,
    pub file: PathBuf,
    #[serde(default)]
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub words: HashMap<String, String>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub casdir: Option<PathBuf>,
    #[serde(default)]
    pub policy: Option<String>,
    // … all existing CLI options
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Encrypt, Decrypt, Store, Fetch, EncryptStore, Passthrough, Verify,
    Inspect, List, Manifest, Attest, Scm,
    // …
}

pub fn run_config(cfg: EnprotConfig) -> Result<()> { /* … */ }
```

CLI compiles the parsed clap types to `EnprotConfig`, then calls `run_config`. FFI JSON-deserializes directly to `EnprotConfig`.

## Implementation plan

1. Define `EnprotConfig` + `Operation`.
2. Extract shared dispatch from `app_main` into `run_config`.
3. CLI compiles clap → `EnprotConfig`.
4. FFI replaces `json_to_argv` with direct deserialization.
5. Generate `docs/schemas/config-v1.json` from `schemars`.

## Test plan

- [ ] CLI + FFI exercise identical code paths.
- [ ] JSON schema matches both bindings' expectations.
- [ ] No behavioral regression.

## Out of scope

- gRPC / protobuf wire format (JSON is enough).
- Async config execution.
