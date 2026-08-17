# Contributing to enprot

Thank you for your interest in contributing to enprot! This document
covers everything from your first build to releasing a new version.

**By participating, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).**

## Table of contents

1. [Development Setup](#development-setup)
2. [Testing](#testing)
3. [Code Quality](#code-quality)
4. [Pull Request Process](#pull-request-process)
5. [Architecture Overview](#architecture-overview)
6. [Security Review](#security-review)
7. [Worktree Workflow](#worktree-workflow)
8. [Release Process](#release-process)
9. [Adding TODOs](#adding-todos)

## Development Setup

1. Install [Botan 3](https://botan.randombit.net/) (`brew install botan` on macOS; see `ci/install.sh` for Linux).
2. Install [librnp](https://github.com/rnpgp/rnp) (`brew install rnp` on macOS; if it conflicts, `brew link --overwrite rnp`).
3. Clone the repo and build:

```sh
git clone https://github.com/engyon/enprot.git
cd enprot
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" cargo build
```

On macOS, test binaries need `DYLD_LIBRARY_PATH` to find `librnp.0.dylib`:

```sh
PKG_CONFIG_PATH="$(brew --prefix)/lib/pkgconfig" DYLD_LIBRARY_PATH="$(brew --prefix)/lib" cargo test
```

4. Install the pre-commit hook:

```sh
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

This runs `cargo fmt --check`, `cargo clippy -D warnings`, and `typos` before every commit. Skip temporarily with `SKIP_PRECOMMIT=1 git commit ...`.

## Testing

```sh
cargo test                              # full suite (unit + integration + proptest)
cargo test --test integration           # integration tests only
cargo test --test proptest_roundtrip    # crypto round-trip properties
cargo test --test proptest_invariants   # pipeline invariants (store/fetch/encrypt)
cargo test --test rsd-conformance       # RSD spec conformance fixtures
cargo test <name>                       # single test by name substring
```

Tests use real Botan, real `ParseOps`, real files. No mocks.

**Conformance fixtures** live in `tests/rsd-conformance/fixtures/`. Each
`.ept` file is a self-contained test input + expected-tree assertion. See
[TODO.complete/30](TODO.complete/30-rsd-conformance-expand.md) for the
fixture-authoring guide.

**Property tests** (`tests/proptest_*.rs`) run 256 random cases per
property. If a case fails, proptest saves a minimised reproduction in
`tests/<file>.proptest-regressions` — commit that file so the regression
is locked.

## Code Quality

- **Format**: `cargo fmt --all --check`
- **Lint**: `cargo clippy --all-targets -- -D warnings`
- **Spell check**: `typos` (config in `typos.toml`)
- **License/advisory check**: `cargo deny check licenses advisories` (config in `deny.toml`)
- **Unused deps**: `cargo machete` (if installed)

All of these run in CI and are required checks on every PR.

### Typed errors

The codebase is mid-migration from `Error::msg(format!(...))` (opaque
strings) to typed variants (`Error::InvalidArg { arg, reason }`,
`Error::Extfield { field, reason }`, etc.). See
[TODO.complete/26](TODO.complete/26-typed-errors-callsite-migration.md)
for the migration guide. **New code should use typed variants, not
`Error::msg`.**

## Pull Request Process

1. Fork the repository (or use a worktree — see below).
2. Create a feature branch from `main`.
3. Make your changes. Ensure all checks pass.
4. Open a PR against `main`. Reference any TODO.complete entry the PR
   addresses.

### What reviewers look for

- **Correctness**: tests cover the new behavior; existing tests still pass.
- **API stability**: changes to public items respect
  [docs/api-stability.md](docs/api-stability.md).
- **Security**: crypto changes need a security review (see below).
- **DRY / OCP / MECE**: prefer extension over modification; one concern
  per function/module; no duplicate logic.
- **Performance**: new code paths are instrumented if hot (see
  [TODO.complete/31](TODO.complete/31-tracing-instrumentation-expand.md)).

### Commit message conventions

- Use the conventional-commits prefix: `feat(scope):`,
  `fix(scope):`, `refactor(scope):`, `test(scope):`, `docs(scope):`,
  `ci(scope):`, `chore(scope):`.
- Subject line ≤ 72 chars.
- Body explains *why*, not *what* (the diff shows what).
- **No AI attribution** — no `Co-authored-by: Claude` or similar trailers.
  The commit author is the human who directed the work.
- **No `git add -A`** — stage explicit file paths.

## Architecture Overview

See `CLAUDE.md` for a detailed architecture guide: module structure,
`ParseOps` decomposition, crypto stack, CLI wiring, and the `etree/`
module split.

The high-level data flow:

```
CLI (clap) → RunConfig → pipeline::run → parse → transform → tree_write → output file
```

Each subcommand lives in `src/cli/<name>.rs` (post-#236 decomposition).
Crypto primitives live in `src/{prot,pbkdf,cipher,crypto}.rs`. The chain
anchor DAG lives in `src/ledger/`.

## Security Review

Crypto changes — anything touching `src/{prot,pbkdf,cipher,crypto,pki}.rs`
or the wire format — need **two reviewers**, one of whom should have
security context.

Cross-reference against [docs/threat-model.md](docs/threat-model.md):

- Does the change affect an **in-scope guarantee** (G1–G8)? If yes, add
  or update the test that verifies it.
- Does it fall under an **out-of-scope non-guarantee** (N1–N8)? If yes,
  document why the change is safe despite the non-guarantee.
- Does it introduce a new timing-sensitive comparison? If yes, use
  `subtle::ConstantTimeEq`. The principle: **secret-derived data needs
  constant-time comparison; everything else can use `==`** — don't
  blanket-apply `ct_eq`, it obscures which comparisons actually
  guard secrets. The audited classification:

  | Comparison | Timing-sensitive? | Why |
  |---|---|---|
  | CAS hash (`load` verify) | no | content-derived, not secret |
  | Botan AEAD/MAC tag checks | no | Botan verifies internally in constant time |
  | `pki::verify` signature result | no | Botan primitive |
  | WORD names, filenames, cipher names, anchors' indices/timestamps | no | public data |
  | Password vs stored reference (none today) | **yes, when added** | byte-wise recovery via timing |
  | Re-derived key vs stored PHC (none today) | **yes, when added** | as above |
  | Future HMAC/HKDF tag checks | **yes, when added** | as above |

  Raw `==` on `Vec<u8>`/`&str` short-circuits at the first mismatch —
  that leak is what `ct_eq` exists to close.

**Reporting security issues**: see [SECURITY.md](SECURITY.md). Do NOT
open a public issue for suspected vulnerabilities.

## Worktree Workflow

For parallel work on multiple features, use git worktrees (not branch
switching in a single checkout). The `claude-code` CLI has first-class
worktree support:

```
/ worktree <name>
```

Each worktree gets its own branch from `origin/main` and its own build
directory. When done, exit the worktree (the work is preserved on the
branch).

This avoids the "switch branch, rebuild, switch back, rebuild" cycle
that wastes CI minutes and risks leaving stale artifacts.

## Release Process

Releases are tag-driven. release-plz (`.github/workflows/release.yml`)
runs on every push to `main` and creates a release PR with a version
bump + changelog. When that PR is merged:

1. release-plz publishes to crates.io.
2. release-plz pushes a `v`-prefixed tag (e.g. `v0.5.14`).
3. The tag push triggers `.github/workflows/deploy.yml` which
   cross-compiles 6 targets, generates man pages + shell completions,
   and publishes to GitHub Releases + Snap Store.

Manual release (emergency only):

```sh
cargo release <level>    # level: patch / minor / major
git push --tags
```

### Release checklist

- [ ] All CI green on `main`.
- [ ] `CHANGELOG.md` reflects the changes since the last release.
- [ ] Version numbers in `Cargo.toml` + `enprot-ffi/Cargo.toml` agree.
- [ ] [docs/threat-model.md](docs/threat-model.md) reviewed for the
  new release.
- [ ] [docs/api-stability.md](docs/api-stability.md) classification
  reflects the new code.

## Adding TODOs

Outstanding work is tracked in [TODO.complete/](TODO.complete/). Each
TODO is a self-contained spec with: problem, goals, design,
implementation plan, test plan, out-of-scope.

To add a new TODO:

1. Pick the next available number (e.g. `50-new-feature.md`).
2. Use the [TODO template](TODO.complete/README.md#maintenance) structure.
3. Add a row to the appropriate section in
   [TODO.complete/README.md](TODO.complete/README.md).
4. PR the new TODO + README update.

When a TODO ships, update its status line to `done` with the PR number.
Split large TODOs (e.g. #02 → #02 + #26) rather than bloating a single
file.

## Getting Help

- **Issues**: <https://github.com/engyon/enprot/issues>
- **Discussions**: <https://github.com/engyon/enprot/discussions>
- **Security**: open.source@ribose.com (see [SECURITY.md](SECURITY.md))

We welcome contributions of all sizes — from typo fixes to new
subcommands. If you're not sure where to start, the
["good first issue"](https://github.com/engyon/enprot/labels/good%20first%20issue)
label lists approachable tasks.
