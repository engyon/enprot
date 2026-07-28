# 12 — Reproducible builds

**Priority**: P1
**Status**: done (config); certification tracked separately

## Problem

enprot ships deterministic AEAD (`aes-256-gcm-det`) and deterministic
signatures (Ed25519). The CAS layer relies on input determinism.
But the **build itself** isn't reproducible — the same source +
deps can produce different binaries due to:

- Build timestamps embedded in binaries
- Path embedding (debug info, panic messages)
- Build-environment specifics (Cargo profile, linker flags)
- Botan / librnp static linking variations

Without reproducible builds, "I verified this binary matches the
source" requires trusting the builder. With them, anyone can
independently verify.

## Solution

### 1. Strip build-env from binaries

In `Cargo.toml`:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
# Reproducible builds:
panic = "abort"
debug = "line-tables-only"  # stable, no full paths
```

In `.cargo/config.toml`:

```toml
[build]
rustflags = [
    "-C", "link-arg=--build-id=none",  # no build-id hash
    "-C", "remap-path-prefix=/usr/local/cargo=/cargo",  # canonical cargo path
    "-C", "remap-path-prefix=$(pwd)=/src",  # canonical src path
]
```

### 2. Set `SOURCE_DATE_EPOCH`

All build scripts read this env var:

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
```

Botan's `configure.py` honors it; librnp's CMake honors it via
`-DCMAKE_SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH`.

### 3. CI workflow: reproducible-build verification job

```yaml
reproducible-build:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v7
    - run: ./ci/install.sh
    - run: cargo build --release
    - run: sha256sum target/release/enprot > sha-first.txt
    # Reset to clean state, rebuild with different env layout
    - run: rm -rf target/
    - run: |
        cd /tmp
        git clone $GITHUB_REPOSITORY
        cd enprot
        git checkout $GITHUB_SHA
        ./ci/install.sh
        cargo build --release
        sha256sum target/release/enprot > /tmp/sha-second.txt
    - run: diff sha-first.txt /tmp/sha-second.txt
```

If the diff succeeds, the build is reproducible.

### 4. Publish build artifacts + manifest

```yaml
- name: Publish reproducible build manifest
  run: |
    cat sha-first.txt > reproducible-build-${{ github.ref_name }}.txt
    echo "source_commit: ${{ github.sha }}" >> reproducible-build-${{ github.ref_name }}.txt
    echo "built_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> reproducible-build-${{ github.ref_name }}.txt
```

Upload as a release artifact so third parties can verify.

## What this doesn't cover

- Botan / librnp themselves need to be reproducibly built. Both
  have their own reproducible-build efforts; we depend on them.
- macOS codesigning breaks reproducibility — we'd publish unsigned
  + signed variants and document the difference.

## Acceptance criteria

- [x] `Cargo.toml` profile + `.cargo/config.toml` flags added
- [x] `ci/install.sh` exports `SOURCE_DATE_EPOCH`
- [ ] Reproducible-build CI job added
- [ ] Release artifacts include manifest + expected SHA

## Cross-references

- [[13-fuzzing-harness]] — companion quality measure
- [[22-security-audit-prep]] — reproducible builds are audit-ready
