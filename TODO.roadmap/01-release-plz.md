# 01 — release-plz: automated crate publishing

**Priority**: P0
**Status**: specified

## Problem

enprot is published to crates.io via a tag-driven deploy.yml workflow.
This requires manual version bumps, manual tag pushes, and manual Cargo.toml
synchronization. parsanol-rs uses [release-plz](https://release-plz.dev)
for fully automated publishing.

## Solution

Adopt release-plz. On every push to `main`:

1. release-plz parses conventional commits since the last release
2. Determines the new version (patch/minor/major) from commit scope
3. Opens a "Release PR" that updates `Cargo.toml` version + `CHANGELOG.md`
4. When the Release PR is merged, release-plz publishes to crates.io

## Implementation

### `.github/workflows/release.yml`

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
