# Contributing to enprot

Thank you for your interest in contributing to enprot!

## Development Setup

1. Install [Botan 3](https://botan.randombit.net/) (`brew install botan` on macOS; see `ci/install.sh` for Linux).
2. Clone the repo and build:

```sh
git clone https://github.com/engyon/enprot.git
cd enprot
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build
```

3. Install the pre-commit hook:

```sh
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

This runs `cargo fmt --check`, `cargo clippy -D warnings`, and `typos` before every commit. Skip temporarily with `SKIP_PRECOMMIT=1 git commit ...`.

## Testing

```sh
cargo test                              # full suite (unit + integration + proptest)
cargo test --test integration           # integration tests only
cargo test --test proptest_roundtrip    # property-based tests only
cargo test <name>                       # single test by name substring
```

Tests use real Botan, real `ParseOps`, real files. No mocks.

## Code Quality

- **Format**: `cargo fmt --all --check`
- **Lint**: `cargo clippy --all-targets -- -D warnings`
- **Spell check**: `typos` (config in `typos.toml`)
- **License/advisory check**: `cargo deny check licenses advisories` (config in `deny.toml`)
- **Unused deps**: `cargo machete` (if installed)

All of these run in CI.

## Pull Request Process

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make your changes. Ensure all checks pass.
4. Open a PR against `main`.

## Architecture Overview

See `CLAUDE.md` for a detailed architecture guide: module structure, `ParseOps` decomposition, crypto stack, CLI wiring, and the `etree/` module split.

## Security

See `SECURITY.md` for vulnerability reporting. Crypto changes need careful review — the wire format (`pbkdf:` / `cipher:` extfields) is a compatibility contract with existing encrypted documents.
