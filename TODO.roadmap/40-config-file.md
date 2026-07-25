# 40 — Config file + enprot init

**Priority**: P1
**Status**: specified (consolidated from TODO.finalize/05)

## Layered-defaults resolution

1. Built-in defaults
2. `.enprot.toml` (project root, walk up from cwd)
3. `~/.config/enprot/config.toml`
4. `ENPROPT_*` env vars
5. CLI flags (highest precedence)

## TOML format

```toml
casdir = "cas"
lang = "c"
policy = "default"

[encrypt]
cipher = "aes-256-gcm-siv-det"
pbkdf = "argon2"
pbkdf_msec = 100

[chain]
# signer = "confium://session-id"
# auto_anchor = true
```

## Implementation

- Add `serde` + `toml` deps
- `src/config.rs`: Config struct + layered loader
- `enprot init [--global]`: writes template
- Tests: layered resolution, CLI override, malformed TOML error

## Acceptance criteria

- [ ] `enprot init` produces a commented template
- [ ] CLI flags override config values
- [ ] Missing file: falls back silently
