# 19 — Snap auto-publish fix

**Priority**: P2
**Status**: specified

## Problem

`publish-snap` job in `deploy.yml` uses `SNAPCRAFT_RELEASE_LOGIN` secret that may or may not be configured. The job also runs in `continue-on-error` mode if any of the previous jobs fail.

## Goals

- Snap publishes reliably on every release tag.
- Build + publish in `snapcore/action-build@v1` is reproducible from the manifest.
- Failure visibility: if snap fails, the deploy run is marked failed (not silently skipped).

## Design

Update `snap/snapcraft.yaml` to track `latest/stable` base + use `version: $VERSION` substitution via `snap/set-version.sh`. CI passes the version via `SNAPCRAFT_BUILD_ENVIRONMENT_VERSION`.

```yaml
# .github/workflows/deploy.yml
publish-snap:
  name: snap
  needs: [github-release]   # snap only after binaries exist
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v7
      with: { ref: '${{ env.DEPLOY_TAG }}' }
    - name: Set version
      run: |
        VERSION="$(echo "$DEPLOY_TAG" | sed 's/^[^0-9]*//')"
        echo "VERSION=$VERSION" >> $GITHUB_ENV
        sed -i "s/__VERSION__/$VERSION/g" snap/snapcraft.yaml
    - uses: snapcore/action-build@v1
      id: build
      with: { snapcraft_token: '${{ secrets.SNAPCRAFT_RELEASE_LOGIN }}' }
    - uses: snapcore/action-publish@v1
      with:
        store_token: '${{ secrets.SNAPCRAFT_RELEASE_LOGIN }}'
        snap: '${{ steps.build.outputs.snap }}'
        release: stable
```

## Implementation plan

1. Verify `SNAPCRAFT_RELEASE_LOGIN` is set (or document how to obtain).
2. Update snap/snapcraft.yaml with `version: __VERSION__` placeholder.
3. Update deploy.yml publish-snap job.
4. Run `gh workflow run deploy.yml -f tag=enprot-v0.5.13` to test end-to-end.

## Test plan

- [ ] `snapcraft build` succeeds locally (multipass).
- [ ] Snap installs in `ubuntu:24.04` container, `enprot --version` works.
- [ ] Snapcraft store page shows new release within 30 minutes of tag push.

## Out of scope

- Multi-arch snaps (currently x86_64; arm64 needs a separate runner).
- Classic confinement (would simplify packaging but requires manual review).
