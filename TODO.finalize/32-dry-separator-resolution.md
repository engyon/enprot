# Refactoring: DRY up lang-separator resolution

## Why

`run()` (lines 484-503) and `apply_common()` (lines 904-922) duplicate
the exact same logic for resolving `--lang` presets vs explicit `-l/-r`
flags. Two places means two chances to drift; future defaults (e.g.,
adding a `--lang markdown`) require touching both.

This is the textbook DRY violation. Extract to a single function and
have both call sites use it.

## Scope

1. Extract `fn resolve_separators(common: &CommonArgs) -> Separators`
   returning the final left/right strings
2. Both `run()` and `apply_common()` call this; their respective
   inline blocks get deleted
3. Test: explicit `-l/-r` always wins; `--lang python` preset is used
   when no explicit flags; default falls through to `consts::DEFAULT_*`
4. Behavior is byte-identical before/after (golden test against
   `tests/cli/policy.rs` and a few `--lang` invocations)

## Out of scope

- Adding new `--lang` presets (TODO 02 is done; this is just plumbing)
- Removing `apply_common` (still has other uses)

## Acceptance criteria

- One call site for separator resolution
- All separator-related tests still pass
- `cargo clippy` clean
