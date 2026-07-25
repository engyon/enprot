# 02 — Crate split: enprot-core (library) + enprot (CLI binary)

**Priority**: P0
**Status**: specified

## Problem

enprot is a single crate with both library code (`src/lib.rs`) and binary
code (`src/main.rs`). Downstream consumers (Confium, docs.rs, examples)
can only depend on the combined crate, which pulls in CLI deps (clap,
clap_complete) they don't need. The `documentation` field points to a
README, not docs.rs.

## Solution

Split into a Cargo workspace:

```
enprot/
├── Cargo.toml              # workspace root
├── crates/
│   ├── enprot-core/        # library: parsing, crypto, ledger, merkle, capability
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── capability.rs
│   │       ├── cas.rs
│   │       ├── cipher.rs
│   │       ├── crypto.rs
│   │       ├── error.rs
│   │       ├── etree/
│   │       ├── ledger/
│   │       ├── merkle.rs
│   │       ├── password.rs
│   │       ├── pki.rs
│   │       ├── policy/
│   │       ├── prot.rs
│   │       └── utils.rs
│   └── enprot/             # binary: CLI, subcommands
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           └── cli.rs      # (extracted from lib.rs)
```

## Workspace Cargo.toml

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
# ... etc
```

## enprot-core Cargo.toml

```toml
[package]
name = "enprot-core"
description = "Engyon Protected Text (EPT) core library"
documentation = "https://docs.rs/enprot-core"
# ... workspace-inherited fields

[dependencies]
botan = { workspace = true }
thiserror = { workspace = true }
hex = { workspace = true }
# NO clap, NO clap_complete
```

## enprot (binary) Cargo.toml

```toml
[package]
name = "enprot"
description = "Engyon Protected Text (EPT) command-line tool"
# ... workspace-inherited fields

[dependencies]
enprot-core = { path = "../enprot-core", version = "0.5.0" }
clap = { workspace = true }
clap_complete = { workspace = true }
```

## Benefits

- **docs.rs**: `enprot-core` gets full API docs on docs.rs without
  CLI noise. Users searching for "enprot" on docs.rs land on the library.
- **Downstream deps**: Confium, examples, and other crates can depend on
  `enprot-core` without pulling in clap.
- **Compile times**: CLI deps (clap, clap_complete) aren't rebuilt when
  only the library changes.
- **publishing**: release-plz handles both crates independently — a
  library-only change publishes enprot-core; a CLI change publishes both.

## Migration

1. Create `crates/enprot-core/` with all library code
2. Create `crates/enprot/` with CLI code (depends on enprot-core)
3. Update imports: `use enprot_core::...` instead of `use enprot::...`
4. Update integration tests to use `enprot_core::` paths
5. Update deploy.yml binary build path
6. Verify `cargo build --workspace` and `cargo test --workspace`

## Acceptance criteria

- [ ] Workspace structure with two crates
- [ ] `cargo build --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc -p enprot-core --open` shows clean API docs
- [ ] Both crates publish to crates.io via release-plz
