# 10 — Test updates and final verification

## Goal

Update integration tests for the new `assert_cmd` 2.x and `predicates` 3.x
APIs. Run the full suite. Confirm round-trip compat with golden files.

## Files

- `Cargo.toml` — bump `assert_cmd = "2"`, `predicates = "3"`
- `tests/cli/*.rs` — mechanical updates
- `tests/tests.rs` — `Fixture` helper unchanged but uses new deps
- `test-data/*.ept` — verify, regenerate ONLY if a behavior change warrants it

## API deltas

### `assert_cmd` 0.11 → 2.x

| Old | New |
|-----|-----|
| `Command::cargo_bin("enprot")?` | unchanged |
| `.arg(...).assert().success()` | unchanged |
| `.failure()` | unchanged |
| `predicates::str::contains(...)` (predicates 1) | same import, may need `predicate()` adapter in v3 |

### `predicates` 1 → 3

`predicates::str::contains("foo")` still exists. The bigger change is the
`prelude::*` re-exports; if anything broke, it's likely the `.stderr(...)`
chain — check the docs.

### `tempfile` 3.1 → 3.10+

Compatible — no API changes affecting `tempdir()` and `tempdir().path()`.

## Verification matrix

Run all of:

```
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo test                       # full suite, streamed
cargo test --test integration    # integration only
```

### Golden file round-trip check

For each `test-data/*.ept` containing encrypted content, run:

```
enprot <file> -d <word> -k <word>=<pw> -o -     # decrypt
enprot <file> -e <word> -k <word>=<pw>          # re-encrypt
diff against the golden file
```

If round-trip is identity, the upgrade is wire-compatible. If the encrypted
bytes differ from the golden, investigate root cause before regenerating
golden files — a difference means either:
1. PBKDF salt was randomized (use `--pbkdf-salt` to make deterministic).
2. The cipher implementation diverged (.Botan 2 vs 3 behavioral change).
3. The PHC serialization order changed (alphabetical vs insertion order).

(3) is benign — both old and new parsers should accept either ordering.
(1) and (2) need explicit handling.

## Final commit checklist

Before pushing the branch:

- [ ] All `cargo` commands above pass.
- [ ] `grep -rn "&'static str" src/` returns no hits.
- [ ] `grep -rn "extern crate" src/ tests/` returns no hits.
- [ ] CI workflows run green on a feature-branch push.
- [ ] `CHANGELOG` (if present) or commit messages note the Botan 3 migration
      and any behavioral change.

## Rollback

Test file changes are mechanical. If a golden file was regenerated,
explanation belongs in the commit message.
