# 37 — release-plz: CARGO_REGISTRY_TOKEN secret

**Priority**: P0
**Status**: blocked on user action

## Problem

The release-plz workflow (`.github/workflows/release.yml`) is
shipped and will open Release PRs on every push to `main`. But
the `cargo publish` step fails because `CARGO_REGISTRY_TOKEN`
is not set in the repo's GitHub Secrets.

## What the user needs to do

1. Go to https://crates.io/settings/tokens
2. Create a new token with `publish-new` scope
3. Add it as a repo secret named `CARGO_REGISTRY_TOKEN` at
   https://github.com/engyon/enprot/settings/secrets/actions

## Local fallback (interim)

Until the secret is added, the maintainer can publish locally:

```sh
cargo install release-plz
export CARGO_REGISTRY_TOKEN=<token>
release-plz release
```

This publishes to crates.io and pushes the tag; the tag push then
triggers the binary build in `deploy.yml`.

## Acceptance criteria

- [ ] `CARGO_REGISTRY_TOKEN` secret configured
- [ ] First push to main after configuration triggers a Release PR
- [ ] Merging the Release PR publishes to crates.io
