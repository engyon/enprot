# Config file + `enprot init`

## Why

Project-level defaults (.enprot.toml) so callers don't repeat `-c`, `-k
WORD=…`, `--lang`, `--policy` on every invocation. Critical for git
smudge/clean (TODO 06) and any non-interactive workflow.

## Layered-defaults resolution order (highest precedence last)

1. Built-in defaults (`consts::DEFAULT_*`)
2. `.enprot.toml` (project root, walking up from cwd)
3. `~/.config/enprot/config.toml` (user-global, optional)
4. `ENPROPT_*` environment variables
5. CLI flags (`-c`, `-k`, `--lang`, `--policy`, etc.)

Explicit CLI flags always win. Within a single source, a `--key
WORD=PASSWORD` from the CLI replaces the same WORD from config (not
concatenates).

## File format

```toml
# .enprot.toml — project root
casdir = "cas"
lang = "c"               # default host-language preset
policy = "default"

[passwords]
# NOTE: plaintext passwords in config are NOT recommended; use
# ENPROPT_WORD_<NAME>=secret env vars or an OS keychain integration
# (TODO 33 — out of scope for v1).
# Agent_007 = "hunter2"

[encrypt]
cipher = "aes-256-gcm-siv-det"
pbkdf = "argon2"
pbkdf_msec = 100

[chain]                  # Stage 1 (TODO 17) — empty by default
# signer = "path/to/privkey.pem"
# auto_anchor = true     # every encrypt/store/fetch produces an anchor
```

## Scope

1. New module `src/config.rs`:
   - `struct Config { casdir, lang, policy, passwords, encrypt, chain }`
   - `fn load() -> Result<Config>` — walks cwd upward to find
     `.enprot.toml`, then user-global, then env, then built-ins
   - `fn apply_overrides(self, cli: &CommonArgs) -> Self` — CLI wins
2. `Cargo.toml`: add `serde` + `toml` deps
3. `enprot init [--global]` subcommand: writes a default
   `.enprot.toml` template at the project root (or `~/.config/enprot/`)
4. Tests:
   - Layered resolution: env > config > built-in
   - CLI override replaces config value (not concatenates for passwords)
   - Missing file: falls back to env + built-ins silently
   - Malformed TOML: clear error pointing at the file:line
5. Documentation in `docs/config.md`

## Out of scope

- Plaintext password storage recommendations (caller's responsibility)
- OS keychain integration (separate TODO, possibly never)
- Multi-project monorepo support (walk-up is sufficient)
- Hot reload (config is read once at startup)

## Open design questions

- **Layered semantics for repeatable keys** (like `-k`): does CLI
  replace the entire set, or merge? Recommendation: CLI replaces the
  set (matches current `--lang` semantics). Use `[passwords]` table
  for project defaults; CLI is for per-invocation override.
- **Config discovery depth**: walk up how many parent directories?
  Recommendation: stop at first `.git/` or filesystem root, whichever
  comes first.

## Acceptance criteria

- `enprot init` produces a commented template
- Existing flag-only workflows still work without a config file
- All layered-resolution test cases pass
- Documented workflow: commit `.enprot.toml` to the repo for team
  defaults; `.gitignore` user secrets
