# 04 — Non-breaking dependency bumps

## Goal

Bump crate versions that require only minor API surface changes. These are
the deps that ARE NOT the major migrations (Botan, clap, phc — each has its
own phase).

## Files

- `Cargo.toml`
- `src/lib.rs` (validators)
- `src/crypto.rs` (uses `num::Unsigned`)
- `src/prot.rs` (`rpassword::prompt_password_stdout`)
- `tests/cli/*.rs` (`assert_cmd`, `predicates`)

## Approach

| Dep | Before | After | Notes |
|-----|--------|-------|-------|
| `hex` | `0.3` | `0.4` | API compatible (`hex::decode`, `hex::encode`) |
| `num` | `0.2.0` | `0.4` | `num::Unsigned` trait still present; trait path unchanged |
| `phf` | `0.8.0` | `0.11` | `phf_map!` / `phf_set!` macros unchanged |
| `rpassword` | `2` | `7` | `prompt_password_stdout` → `prompt_password` (writes to stderr by default, returns String) |
| `tempfile` | `3.1.0` | `3` | compatible |
| `cpu-time` | `1.0.0` | `1.0` | unchanged |
| `assert_cmd` | `0.11` | `2` | see test phase (phase 10) |
| `predicates` | `1.0` | `3` | see test phase (phase 10) |

`assert_cmd` and `predicates` are deferred to phase 10 because their major
bumps touch every test file — keep them at the existing pinned versions until
then to keep this phase reviewable.

### `rpassword` 7 API change

`src/prot.rs::get_password` currently calls
`rpassword::prompt_password_stdout(&prompt).unwrap()`. The v7 API is
`rpassword::prompt_password(prompt)` (returns `io::Result<String>`); it writes
the prompt to stderr by default, which matches CLI conventions better than
stdout. Update the call sites.

## Verification

```
cargo check --all-targets
cargo test --lib           # unit tests
```

## Rollback

Revert `Cargo.toml` and the `rpassword` call site.
