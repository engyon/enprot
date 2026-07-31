# 07 — Decompose `src/cli.rs`

**Priority**: P1
**Status**: specified

## Problem

`src/cli.rs` is a 2,900-line file with every CLI subcommand, argument type, helper function, and runner crammed together. It compiles slowly, is hard to navigate, and new subcommands touch a file that 20+ other people are also touching.

## Goals

Split into per-subcommand modules under `src/cli/`:

```
src/cli/
├── mod.rs            # Cli struct + CommonArgs + dispatch via match
├── common.rs         # CommonArgs, OutputArgs, shared types
├── encrypt.rs        # run() + helpers for encrypt/decrypt/store/fetch/encrypt-store/passthrough
├── inspect.rs        # run_inspect
├── list.rs           # run_list
├── manifest.rs       # run_manifest
├── attest.rs         # run_attest
├── merge_driver.rs   # run_merge_driver, run_resolve, run_conflicts
├── smudge.rs         # run_smudge_clean
├── scm.rs            # run_scm
├── init_config.rs    # init_config
└── util.rs           # process_one_file, file_pairing, etc.
```

Each module is ≤ 400 lines. Dispatch in `mod.rs` is a single match.

## Design

Keep all public exports at `cli::*` (via `pub use`) for back-compat. No behavioral changes.

## Implementation plan

1. Create `src/cli/` + `mod.rs` with the match-dispatch.
2. Move each `run_*` function + its subcommand-specific types one at a time (one commit per subcommand).
3. Final commit removes the original `src/cli.rs`.

## Test plan

- [ ] All existing tests pass.
- [ ] `cargo doc` renders the new module structure.
- [ ] `cargo check` time drops by ~30% (fewer file-level recompiles).

## Out of scope

- Splitting the binary crate into multiple crates.
- Subcommand plugin architecture (dynamic dispatch).
