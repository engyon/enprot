# 02 — Crate split: enprot-core (library) + enprot (CLI binary)

**Priority**: P0
**Status**: specified, with a partial-split interim path

## Problem

enprot is a single crate with both library code (`src/lib.rs`) and
binary code (`src/main.rs`). Downstream consumers (Confium,
docs.rs, examples) can only depend on the combined crate, which
pulls in CLI deps (clap, clap_complete) they don't need.

## Interim path: feature-gated CLI deps (smaller change)

Before doing the full workspace split, gate the CLI-only
dependencies behind a `cli` feature. Downstream Rust consumers
do `enprot = { version = "...", default-features = false }` and
get the library without clap. This is a one-commit change:

```toml
[features]
default = ["cli"]
cli = ["dep:clap", "dep:clap_complete"]

[dependencies]
clap          = { version = "4.5", features = ["derive", "wrap_help"], optional = true }
clap_complete = { version = "4", optional = true }
```

Library code in `src/lib.rs` must not transitively reference
clap types. The CLI dispatch (currently in `src/lib.rs`) moves
to `src/cli.rs` and is gated by `#[cfg(feature = "cli")]`. The
binary (`src/main.rs`) enables the feature unconditionally.

This unblocks downstream library use without the workspace
refactor's churn. Acceptable as a permanent state if the lib
API surface stays small.

## Full solution: workspace split (target state)

When the lib API is stable enough to commit to a `0.x` boundary,
split into a Cargo workspace:

```
enprot/
├── Cargo.toml              # workspace root
├── crates/
│   ├── enprot-core/        # library: parsing, crypto, ledger, merkle, capability
│   │   └── ...
│   └── enprot/             # binary: CLI, subcommands
│       └── ...
```

See the original spec below for the workspace layout.

## Original workspace layout

```toml
[workspace]
resolver = "2"
members = ["crates/enprot-core", "crates/enprot"]

[workspace.package]
version = "0.5.0"
edition = "2024"
authors = ["Ribose Inc. <open.source@ribose.com>"]
license = "BSD-2-Clause"
repository = "https://github.com/engyon/enprot"
homepage = "https://github.com/engyon/enprot"

[workspace.dependencies]
botan = { version = "0.11", features = ["botan3", "pkg-config"] }
thiserror = "2"
hex = "0.4"
```

## Acceptance criteria (interim)

- [ ] `default = ["cli"]` feature ships
- [ ] `cargo build --no-default-features` produces a library-only build
- [ ] Library code has zero clap references
- [ ] Existing CLI behaviour unchanged when `cli` is enabled

## Acceptance criteria (full split, future)

- [ ] Workspace structure with two crates
- [ ] `cargo build --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc -p enprot-core --open` shows clean API docs
- [ ] Both crates publish to crates.io via release-plz

## Recommendation

Ship the interim path now; defer the full split until the lib
API has stabilised through one or two minor releases. The
feature-gated approach gives downstream library users what they
need today without committing to a public API boundary that's
still evolving.
