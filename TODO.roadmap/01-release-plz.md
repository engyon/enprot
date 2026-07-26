# 01 — release-plz: automated crate publishing

**Priority**: P0
**Status**: workflow shipped; awaiting `CARGO_REGISTRY_TOKEN` secret

## Problem

enprot is published to crates.io via a tag-driven deploy.yml workflow.
This requires manual version bumps, manual tag pushes, and manual
Cargo.toml synchronization. parsanol-rs uses
[release-plz](https://release-plz.dev) for fully automated
publishing.

## Current state

- `.github/workflows/release.yml` — shipped. Triggers on push to
  `main`, runs release-plz, opens a Release PR with version bump
  + CHANGELOG.
- `release-plz.toml` — shipped.
- **Missing**: `CARGO_REGISTRY_TOKEN` secret in repo settings.
  Until that's added, the workflow runs but the publish step
  fails. The Release PR still opens (release-plz uses
  `GITHUB_TOKEN` for that), but merging it doesn't publish.

## Local-token workflow (interim)

Until the secret is added, the maintainer can run release-plz
locally:

```sh
cargo install release-plz
export CARGO_REGISTRY_TOKEN=<token from https://crates.io/settings/tokens>
release-plz release
```

This publishes to crates.io and pushes the tag locally; the tag
push then triggers the binary-build workflow in deploy.yml. Same
end state as the CI flow, just initiated from the maintainer's
machine.

## Solution (full CI flow when secret lands)

On every push to `main`:

1. release-plz parses conventional commits since the last release
2. Determines the new version (patch/minor/major) from commit scope
3. Opens a "Release PR" that updates `Cargo.toml` version + `CHANGELOG.md`
4. When the Release PR is merged, release-plz publishes to crates.io

## Implementation

### `.github/workflows/release.yml` (shipped)

```yaml
name: Release
permissions:
  pull-requests: write
  contents: write
on:
  push:
    branches: [main]
jobs:
  release-plz:
    name: Release-plz
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@stable
      - uses: MarcoIeni/release-plz-action@v0.5
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

### `release-plz.toml`

```toml
[workspace]
# Use the Cargo.toml version as the source of truth
allow_dirty = true

[[package]]
name = "enprot"
```

### Secrets required

- `CARGO_REGISTRY_TOKEN` — crates.io API token (user creates at
  https://crates.io/settings/tokens, adds to repo Secrets)

### Conventional commits

The team must use conventional commit format for release-plz to work:
- `feat:` → minor version bump
- `fix:` → patch version bump
- `feat!:` / `BREAKING CHANGE:` → major version bump
- `chore:`, `docs:`, `refactor:` → no version bump

Existing commit history doesn't need retroactive conversion — release-plz
starts from the first release tag it finds.

### Migration from tag-driven deploy.yml

1. Keep the existing deploy.yml for binary releases (GitHub Releases + Snap)
2. Add release.yml for crates.io publishing
3. Remove the `cargo publish` step from deploy.yml (release-plz handles it)
4. The tag push (for binary builds) happens AFTER the release PR merges —
   release-plz creates the tag automatically

## Acceptance criteria

- [ ] release-plz workflow added
- [ ] `CARGO_REGISTRY_TOKEN` secret configured
- [ ] First push to main triggers a release PR (or no-op if no releasable commits)
- [ ] Merging the release PR publishes to crates.io
- [ ] Tag is created automatically for binary build workflow
