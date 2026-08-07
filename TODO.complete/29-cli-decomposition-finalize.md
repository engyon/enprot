# 29 — Finalize cli.rs decomposition + reduce mod.rs surface

**Priority**: P2
**Status**: specified (post-#236)

## Problem

After #236 ships, `src/cli/mod.rs` shrinks from ~3260 to ~1220 lines.
The remaining 1220 lines are:

| Section | Lines | Contents |
|---|---|---|
| Module header + imports | ~50 | license, doc comment, `use` statements |
| `mod` declarations | ~10 | cap, chain_head_cmd, init, inspect, list, merge_cmd, pipeline, pki_cmd, provenance_cmd, smudge, verify, verify_chain |
| `Cli` + `Command` + `*Subcmd` clap structs | ~700 | the CLI surface — clap derive types |
| `app_main` | ~150 | dispatch entry point |
| `with_config` / `apply_config` | ~50 | config-file merging |
| clap value parsers | ~80 | `parse_word_password`, `parse_casdir`, etc. |
| `make_policy` / `resolve_policy` / `resolve_separators` / `apply_common` / `build_anchor_config` / `walk_for_chains` / `capability_to_dto` (all `pub(super)`) | ~180 | shared helpers |

The clap struct block dominates. The shared helpers are tiny but
clutter the dispatch file.

## Goals

- `mod.rs` < 500 lines (currently ~1220). The dispatch file should
  be **only** the dispatch surface: `Cli`/`Command` enums, `app_main`,
  and config bootstrap.
- All shared helpers move to dedicated modules.
- The clap struct definitions are split by subcommand so each
  per-subcommand module owns its own arg structs (MECE).

## Design

### Split clap structs to per-command modules

Today all `*Subcmd` structs live in `mod.rs` because they're
referenced from the central `Command` enum. Move each one next to
the code that consumes it:

```
src/cli/
├── mod.rs                    # Cli, Command, app_main, dispatch
├── common.rs                 # CommonArgs, OutputArgs, EncryptOpts, apply_common, with_config, apply_config
├── parse_helpers.rs          # parse_word_password, parse_casdir, parse_output_dir, parse_positive_*
├── policy.rs                 # make_policy, resolve_policy, resolve_separators
├── shared/                   # cross-module helpers that don't fit elsewhere
│   ├── anchors.rs            # build_anchor_config, walk_for_chains, capability_to_dto
│   └── mod.rs
└── <per-subcommand>.rs       # each module owns its Subcmd structs + run()
```

After the split:

```rust
// src/cli/inspect.rs (post-#236 + this TODO)
#[derive(Args, Debug)]
pub struct InspectSubcmd {
    /// File to inspect, or "-" for stdin.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,
}

pub fn run(a: InspectSubcmd, common: super::common::CommonArgs) -> Result<()> {
    // ...
}
```

```rust
// src/cli/mod.rs (post-this-TODO)
use clap::{CommandFactory, Parser, Subcommand};

mod common;
mod parse_helpers;
mod policy;
mod shared;

// Per-subcommand modules — each owns its Subcmd + run().
mod cap;
mod chain_head_cmd;
mod init;
mod inspect;
// ... etc.

#[derive(Parser)]
pub struct Cli { /* ... */ }

#[derive(Subcommand)]
pub enum Command {
    Inspect(inspect::InspectSubcmd),
    // ...
}

pub fn app_main<I, T>(args: I) -> Result<()> {
    let cli = Cli::parse_from(args);
    match cli.command {
        Command::Inspect(a) => inspect::run(a, cli.common),
        // ...
    }
}
```

### What stays in `mod.rs`

Only the **dispatch surface**:

- `Cli` (top-level)
- `Command` (the subcommand enum)
- `app_main`
- Module declarations

Everything else moves. Target: ~150-200 lines.

## Implementation plan

Each step is its own commit:

1. Extract `CommonArgs` + `OutputArgs` + `EncryptOpts` to `src/cli/common.rs`.
2. Extract config helpers (`with_config`, `apply_config`) to `src/cli/common.rs`.
3. Extract `parse_*` value parsers to `src/cli/parse_helpers.rs`.
4. Extract `make_policy` + `resolve_policy` + `resolve_separators` to `src/cli/policy.rs`.
5. Extract anchor helpers to `src/cli/shared/anchors.rs`.
6. For each per-subcommand module: move its `*Subcmd` structs into the module.
7. Update `Command` enum to reference the moved structs.
8. Verify `mod.rs` is under 500 lines.

This is a big mechanical change. Land it as a stack of small PRs
(one step per PR) to keep review tractable.

## Test plan

- [ ] After each step: `cargo build`, `cargo test`, fmt, clippy all pass.
- [ ] Final `mod.rs` is under 500 lines.
- [ ] No `pub(super)` helpers remain in `mod.rs` (they all moved).
- [ ] No `*Subcmd` struct definitions remain in `mod.rs`.

## Out of scope

- Splitting `common.rs` further (e.g. `config.rs` for TOML loading).
  Do this only if common.rs grows beyond ~300 lines.
- Renaming existing modules. The `*_cmd` suffix is documented in
  CLAUDE.md as avoiding `crate::*` name collisions; keep it.
- Merging the per-subcommand modules into a flat `src/cli_*` layout.
  The current nested-module layout is fine.
