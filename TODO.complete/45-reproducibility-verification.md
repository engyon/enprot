# 45 — Reproducibility verification

**Priority**: P1
**Status**: specified

## Problem

enprot's releases cross-compile to 6 targets, build Botan from
source on Windows, and link against system libraries on Linux/macOS.
A release built today should produce byte-identical binaries to one
built tomorrow — otherwise supply-chain attackers have a place to
hide.

Current state:
- `.cargo/config.toml` has `--remap-path-prefix` for path remapping.
- No CI step verifies that two builds of the same commit produce
  identical artifacts.
- The deploy workflow uploads binaries built once; nobody re-builds
  to check.

## Goals

- A `reproducibility-check` CI job that builds the same commit twice
  with different environment variables and asserts byte-identical
  output.
- Reproducibility issues are documented with a known-issues list
  (e.g., "Windows MSVC embeds a build timestamp; not currently
  reproducible").
- A `reproducible-builds.md` doc explaining how third parties can
  independently verify a release.

## Design

### CI job shape

```yaml
# .github/workflows/reproducibility.yml
name: reproducibility
on:
  push:
    tags: ['v*']
  workflow_dispatch:

jobs:
  build-twice:
    strategy:
      matrix:
        target: [x86_64-unknown-linux-musl, aarch64-apple-darwin, ...]
    runs-on: ubuntu-latest  # or matching OS
    steps:
      - uses: actions/checkout@v7
      # First build
      - run: ./ci/build-static.sh --target ${{ matrix.target }}
      - run: cp target/release/enprot enprot-build1
      # Clean and rebuild with different env
      - run: cargo clean
      - run: ./ci/build-static.sh --target ${{ matrix.target }}
        env:
          FORCE_REBUILD: '1'  # bust any caches
      # Compare
      - run: diff enprot-build1 target/release/enprot
      - run: sha256sum enprot-build1 target/release/enprot
```

### Sources of nondeterminism (audit)

| Source | Mitigation |
|---|---|
| Build timestamps embedded by linkers | Use `SOURCE_DATE_EPOCH` |
| Path leakage (`/home/runner/...`) | `--remap-path-prefix` (done) |
| Random ordering in HashMap iteration | Sort keys before serialisation |
| Build ID generation | Force a fixed build ID via LDFLAGS |
| Compression metadata (gzip timestamps) | Use `gzip -n` |
| Windows PDB timestamps | Use `/DEBUG:FASTLINK` (CI #237) |

### `reproducible-builds.md`

```
docs/reproducible-builds.md

## How to verify a release

1. Download the release binary from GitHub Releases.
2. Rebuild from source with the same tag:
       git checkout v0.5.13
       ./ci/build-static.sh --target x86_64-unknown-linux-musl
3. Compare SHA-256:
       sha256sum target/x86_64-unknown-linux-musl/release/enprot
       sha256sum downloaded-enprot
4. The two hashes must match.

## Known non-reproducible elements

- Windows MSVC build embeds a build timestamp in the PDB.
- macOS codesign step adds a unique signature per build.

See [docs/known-issues.md] for the full list.
```

## Implementation plan

1. Audit each release target for nondeterminism sources.
2. Fix what's fixable (SOURCE_DATE_EPOCH, sorted HashMap keys).
3. Add `reproducibility.yml` CI workflow.
4. Document `reproducible-builds.md`.
5. Tag the first reproducible release; document in CHANGELOG.

## Test plan

- [ ] At least one target (Linux musl) builds reproducibly.
- [ ] `diff` between two builds returns 0.
- [ ] Third-party verification instructions work end-to-end.
- [ ] Non-reproducible elements are documented.

## Out of scope

- Reproducibility of Botan itself (upstream concern).
- Reproducibility of Rust toolchain (deferred to rustup reproducibility).
- A web service that verifies releases (organisational, not technical).
