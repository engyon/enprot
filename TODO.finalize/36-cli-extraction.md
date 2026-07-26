# 36 — CLI code extraction for feature-gated library builds

**Priority**: P1
**Status**: done

## Problem

TODO.roadmap/02 added `[features] default = ["cli"] cli = []` to
Cargo.toml, but the `clap` and `clap_complete` deps remain
non-optional. The CLI structs (`CommonArgs`, `Command`, all
`*Subcmd` types, `app_main()`) are defined in `src/lib.rs`
alongside library code, so making the deps optional would break
compilation of the library target.

Downstream Rust consumers who want `enprot` as a library (for
parsing, crypto, capability-model, or chain-anchor operations)
must still pull in clap + clap_complete — ~2 MB of compiled code
they don't use.

## Solution

Extract all clap-dependent code from `src/lib.rs` into a new
`src/cli.rs` module gated by `#[cfg(feature = "cli")]`. Library
code stays in `src/lib.rs`; CLI code moves to `src/cli.rs`.

### Files to move into `src/cli.rs`

- `Cli` struct (`#[derive(Parser)]`)
- `CommonArgs` struct (`#[derive(Args)]`)
- `OutputArgs`, `EncryptOpts` structs
- `Command` enum (`#[derive(Subcommand)]`)
- All `*Subcmd` structs (`EncryptSubcmd`, `SignSubcmd`, etc.)
- `app_main()` and all `run_*()` / `pki_*()` handler functions
- `resolve_separators()`, `apply_common()`, `make_policy()`
- `parse_word_password()`, `parse_casdir()`, `parse_output_dir()`
- `append_sig_ext()`, `pair_inputs_to_outputs()`

### Files that stay in `src/lib.rs` (library-only)

- All `pub mod` declarations
- `pub use error::{Error, Result};`
- `AnchorConfig` — move to `src/etree/mod.rs` since it's a
  `ParseOps` field, not a CLI concern.

### Cargo.toml changes

```toml
[features]
default = ["cli"]
cli = ["dep:clap", "dep:clap_complete"]

[dependencies]
clap           = { version = "4.5", features = ["derive", "wrap_help"], optional = true }
clap_complete  = { version = "4", optional = true }
```

### src/main.rs

```rust
fn main() {
    enprot::cli::app_main(std::env::args_os()).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
}
```

### src/lib.rs (after extraction)

```rust
// ... module declarations ...
#[cfg(feature = "cli")]
pub mod cli;
```

## Acceptance criteria

- [ ] `cargo build --no-default-features` produces a library-only build
- [ ] `cargo build` (default features) produces the full CLI binary
- [ ] `cargo test` passes with both `--all-features` and `--no-default-features`
- [ ] Library code has zero `clap` references
- [ ] `AnchorConfig` lives in `etree/mod.rs`, not `lib.rs`
