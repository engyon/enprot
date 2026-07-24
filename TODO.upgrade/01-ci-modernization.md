# 01 — CI modernization

## Goal

Update GitHub Actions workflows to current (2026) action versions and replace
archived/unmaintained actions. Drop deprecated `::set-env` usage. Add a clippy
gate. Bump Botan version to 3.x.

## Files

- `.github/workflows/tests.yml`
- `.github/workflows/deploy.yml`
- `ci/install.sh`, `ci/install.ps1`
- `ci/botan-modules` (add `gcm_siv`)

## Approach

### `tests.yml`

| Before | After | Reason |
|--------|-------|--------|
| `actions/checkout@v1` | `actions/checkout@v4` | v1 unmaintained |
| `actions-rs/toolchain@v1` | `dtolnay/rust-toolchain@stable` | actions-rs archived 2023 |
| `cargo fmt -- --check $(find src -name '*.rs')` | `cargo fmt --all --check` | standard idiom |
| (none) | new `check-clippy` job running `cargo clippy --all-targets -- -D warnings` | code quality gate |
| `BOTAN_VERSION: 2.13.0` | `BOTAN_VERSION: 3.7.0` | Botan 3 |
| `RUST_BACKTRACE: full` (env) | keep | still useful |

### `deploy.yml`

| Before | After | Reason |
|--------|-------|--------|
| `actions/checkout@v1` | `actions/checkout@v4` | |
| `actions-rs/toolchain@v1` | `dtolnay/rust-toolchain@stable` | |
| `actions/upload-artifact@v1` | `actions/upload-artifact@v4` | v1 disabled by GitHub |
| `actions/download-artifact@v1` | `actions/download-artifact@v4` | v1 disabled |
| `actions/setup-python@v1` | `actions/setup-python@v5` | |
| `::set-env name=FOO::bar` | `echo "FOO=bar" >> $GITHUB_ENV` | set-env removed Nov 2020 |
| `samuelmeuli/action-snapcraft@v1` | `snapcore/action-build@v1` + `snapcore/action-publish@v1` | samuelmeuli action archived |
| `BOTAN_VERSION: 2.13.0` | `BOTAN_VERSION: 3.7.0` | |
| `CROSS_VERSION: 0.1.16` | `CROSS_VERSION: 0.2.5` | cross moved on |

The `git clone https://github.com/riboseinc/create-github-release` step is
fragile. Leave as-is unless we want to expand scope — flag for follow-up.

### `ci/install.sh`

- Update to clone `--branch "$BOTAN_VERSION"` where `$BOTAN_VERSION=3.7.0`.
- Botan 3 needs a C++20 compiler; `g++` from Ubuntu 22.04+ is fine.

### `ci/botan-modules`

Add `gcm_siv` (needed for AES-256/GCM-SIV via Botan, replacing the hand-rolled
cipher in phase 05).

## Verification

- `yamllint` if available (else manual visual check).
- After all phases, push to a feature branch and confirm `tests.yml` runs
  cleanly on Ubuntu/macOS/Windows.

## Rollback

Revert the workflow files; the source-tree changes (other phases) do not
depend on this phase.
