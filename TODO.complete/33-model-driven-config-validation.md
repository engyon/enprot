# 33 — Model-driven configuration validation

**Priority**: P1
**Status**: specified

## Problem

`CommonArgs`, `OutputArgs`, `EncryptOpts`, and the various `*Subcmd`
structs are all clap-derived. Clap handles *syntactic* validation
(required args present, types parse, value-parser rules honored).
Nobody handles *semantic* validation:

- `--fips` + `--policy default` → conflict (FIPS forces NIST).
- `--signer` without `--anchor` → no-op (signer file is loaded but never used).
- `--word` not referenced in any input file → silent success.
- `--output-dir` + `-` (stdin) → can't write stdin to a directory.
- `--jobs 16` on a 2-core machine → wasted scheduling overhead.
- `--pbkdf-msec 1` → PBKDF weaker than policy floor.

Each is discovered late (mid-pipeline) or silently misused. The
"configure → use" boundary has no validation gate.

## Goals

- A typed `EnprotConfig` that captures the fully-resolved
  configuration **before** any file is processed.
- Validation runs once at startup; invalid configs fail with a
  specific `Error::InvalidArg` per problem, listing all issues (not
  just the first).
- The pipeline reads from `EnprotConfig`, not from clap structs
  directly. Clap structs become a *transport* layer, not the model.
- Library consumers (FFI, tests, downstream crates) can construct
  an `EnprotConfig` directly without going through clap.

## Design

### Layered model

```
┌─────────────────────────────────────────────────┐
│  clap Cli / CommonArgs / *Subcmd                 │  ← transport (argv → structs)
└──────────────────────┬──────────────────────────┘
                       │ resolve + validate
┌──────────────────────▼──────────────────────────┐
│  EnprotConfig (typed, validated, semantic)       │  ← model
│   - operation: Operation                         │
│   - words: Vec<Word>                             │
│   - crypto: CryptoConfig                         │
│   - io: IoConfig                                 │
│   - policy: PolicyRef                            │
│   - anchor: Option<AnchorConfig>                 │
└──────────────────────┬──────────────────────────┘
                       │ consume
┌──────────────────────▼──────────────────────────┐
│  pipeline::run(cfg: EnprotConfig)                │  ← consumer
└─────────────────────────────────────────────────┘
```

### EnprotConfig shape

```rust
// src/config.rs (new)
#[derive(Debug, Clone)]
pub struct EnprotConfig {
    pub operation: Operation,
    pub words: Vec<String>,
    pub files: Vec<PathBuf>,
    pub output: OutputSpec,
    pub crypto: CryptoConfig,
    pub io: IoConfig,
    pub policy: PolicyRef,
    pub anchor: Option<AnchorConfig>,
    pub jobs: usize,
}

#[derive(Debug, Clone)]
pub struct OutputSpec {
    pub mode: OutputMode,           // Stdout | StdinPassthrough | File | Dir
    pub prefix: Option<String>,
    pub format: OutputFormat,       // Text | Json
}

#[derive(Debug, Clone)]
pub struct IoConfig {
    pub casdir: PathBuf,
    pub inline_data: bool,
    pub verbose: bool,
    pub quiet: bool,
    pub max_depth: usize,
}

#[derive(Debug, Clone)]
pub struct PolicyRef {
    pub name: String,                       // "default" | "nist"
    pub fips: bool,
    pub cap_policy: Option<CapPolicy>,      // loaded from --policy-file
}

impl EnprotConfig {
    /// Build from clap-parsed CLI args. Performs the full validation
    /// pass; collects ALL issues before returning (not just the first).
    pub fn from_cli(cli: &Cli) -> Result<Self, ConfigError> {
        let mut issues = Vec::new();
        // ... validation rules ...
        if issues.is_empty() {
            Ok(Self { /* ... */ })
        } else {
            Err(ConfigError { issues })
        }
    }

    /// Construct directly (library/FFI consumers). Skips argv parsing.
    pub fn builder() -> EnprotConfigBuilder { /* ... */ }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration: {}",
    issues.iter().map(|i| format!("\n  - {i}")).collect::<Vec<_>>().join(""))]
pub struct ConfigError {
    pub issues: Vec<ConfigIssue>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigIssue {
    #[error("--fips forces policy=nist but got --policy {0}")]
    FipsPolicyConflict(String),
    #[error("--signer provided without --anchor; the signer file would be unused")]
    SignerWithoutAnchor,
    #[error("--output-dir cannot be combined with stdin input")]
    OutputDirWithStdin,
    #[error("--pbkdf-msec {0} below policy floor {1}")]
    PbkdfMsecBelowFloor(u64, u64),
    // ...
}
```

### Validation rules (initial set)

| Rule | Issue variant |
|---|---|
| `fips=true` and `policy != "nist"` | `FipsPolicyConflict` |
| `signer.is_some()` and `anchor=false` | `SignerWithoutAnchor` |
| `output.mode == Dir` and any input is `-` | `OutputDirWithStdin` |
| `pbkdf_msec < policy.pbkdf_min_msec` | `PbkdfMsecBelowFloor` |
| `jobs > num_cpus` | warning (not error) |
| `word` in `--word` list not present in any input | warning |

## Implementation plan

1. Create `src/config.rs` with `EnprotConfig` + sub-structs.
2. Move the existing `RunConfig` fields into `EnprotConfig` (deprecate `RunConfig` as a thin alias).
3. Implement `EnprotConfig::from_cli` with the initial validation rules.
4. Wire `app_main` to call `from_cli` before dispatching to per-subcommand modules.
5. Convert `pipeline::run` to consume `EnprotConfig`.
6. FFI: expose `enprot_process_config(EnprotConfig)` that skips JSON parsing.

## Test plan

- [ ] Each validation rule has a unit test (positive + negative).
- [ ] `ConfigError` Display lists all issues, one per line.
- [ ] Existing CLI tests pass unchanged (behavior preserved).
- [ ] FFI can build an `EnprotConfig` without going through clap.

## Out of scope

- A `--dry-run` flag (deferred — the validation pass itself is the foundation).
- Schema versioning of `EnprotConfig` (deferred until the FFI surface stabilizes).
- TOML/YAML config files (covered by existing `.enprot.toml`).
