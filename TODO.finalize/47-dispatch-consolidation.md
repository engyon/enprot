# 47 — Consolidate app_main command dispatch

**Priority**: P2
**Status**: done

## Problem

`app_main` in `src/cli.rs` (lines ~855-978) splits command dispatch
across two sites:

1. A chain of 9 `if let Command::X(a) = cli.command { return ... }`
   statements for commands that bypass config loading (init,
   merge-driver, resolve, conflicts, inspect, clean, smudge,
   textconv, manifest, attest, scm).
2. A `match cli.command { ... }` with 9 `unreachable!()` arms
   documenting that those variants were already dispatched above.

The `unreachable!()` arms are runtime panics that fire only if a
developer adds a new `Command` variant and forgets to update the
dispatch. The compiler can't enforce that the two sites stay in
sync. This is an OCP/MECE smell: the dispatch decision is split
across two locations, and the match's "exhaustiveness" is faked.

## Solution

Consolidate into a single `match cli.command` that handles all
variants. Each arm either:
- Calls a no-config handler directly and returns, or
- Falls through to config loading and then dispatches.

The cleanest shape is two functions with disjoint variant sets:

```rust
fn dispatch_no_config(cmd: Command, common: CommonArgs) -> Result<()> { ... }
fn dispatch_with_config(cmd: Command, common: CommonArgs) -> Result<()> { ... }
```

The caller decides which to invoke based on a single match on the
command (or, equivalently, a method on each subcommand type that
declares whether it needs config).

## Acceptance criteria

- [x] No `unreachable!()` arms in `app_main`'s dispatch path
- [x] Adding a new `Command` variant produces a compile error if
      dispatch isn't wired up (exhaustive match)
- [x] All existing subcommands still dispatch correctly
- [x] `cargo test` passes
