---
title: "Reproducible Builds"
layout: ../../../layouts/DocPage.astro
---

**Status**: living document; reviewed on every release.

A reproducible build is one where rebuilding the same source on a
different machine (or at a different time) produces a byte-identical
binary. Reproducibility is the foundation of supply-chain trust: it
lets third parties verify that a published binary actually corresponds
to the published source, closing the gap between "the source looks
safe" and "the binary I'm running is safe."

This document covers:

1. [How to verify a release](#how-to-verify-a-release) — third-party instructions.
2. [How enprot builds reproducibly](#how-enprot-builds-reproducibly) — what the project does.
3. [Known non-reproducible elements](#known-non-reproducible-elements) — honest scope.

## How to verify a release

Given a released `enprot` binary from
[github.com/engyon/enprot/releases](https://github.com/engyon/enprot/releases),
you can confirm it was built from the tagged source by rebuilding and
comparing hashes.

### Prerequisites

- The exact Rust toolchain version used for the release (check the
  release notes or `ci/install.sh`).
- Botan 3 and librnp installed (see `ci/install.sh` for Linux/macOS;
  `ci/install.ps1` for Windows MSVC).
- `SOURCE_DATE_EPOCH` set to the tag's commit timestamp:

  ```sh
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$TAG")
  ```

### Rebuild

```sh
git clone https://github.com/engyon/enprot
cd enprot
git checkout "$TAG"

# Linux musl example. See ci/install.sh for other targets.
./ci/install.sh
cargo build --release --target x86_64-unknown-linux-musl
```

### Compare

```sh
sha256sum target/x86_64-unknown-linux-musl/release/enprot
sha256sum path/to/downloaded-enprot
```

The two hashes must match. If they don't, file an issue with both
hashes, the toolchain version (`rustc --version`), and the OS.

## How enprot builds reproducibly

| Source of nondeterminism | Mitigation |
|---|---|
| Absolute source paths embedded in debug info | `--remap-path-prefix` in [`.cargo/config.toml`](../.cargo/config.toml) |
| Build timestamps embedded by linkers | `SOURCE_DATE_EPOCH` honored by `rustc` and the deploy workflow |
| Random-order HashMap iteration in codegen | Rust's HashMap is non-deterministic only at runtime; compile-time uses sorted iteration where it matters |
| Windows PDB timestamps | `/DEBUG:FASTLINK` (see [`.cargo/config.toml`](../.cargo/config.toml)) |
| macOS codesign unique signatures | Codesigning is applied after the reproducible artifact is uploaded; the unsigned binary is reproducible |

The deploy workflow (`.github/workflows/deploy.yml`) sets
`SOURCE_DATE_EPOCH` for all six release targets before `cargo build`.

## Known non-reproducible elements

These are documented honestly so verifiers know what to expect. The
list is reviewed on every release.

- **Windows MSVC PDB**: the `.pdb` file carries a build timestamp.
  The `.exe` itself is reproducible; the `.pdb` is not. Verifiers
  should compare `.exe` hashes, not `.pdb` hashes.
- **macOS code signature**: `codesign` produces a unique signature
  per invocation. The unsigned `enprot` binary in the release tarball
  is reproducible; the signed `.app` bundle is not. To verify, strip
  the signature (`codesign --remove-signature`) before hashing.
- **Botan version drift**: Botan is linked as a system library on
  Linux/macOS and built from source on Windows. Different Botan
  patch versions produce different binaries. Verifiers must match the
  exact Botan version noted in the release (CI pins Botan 3.7.0).

## Verification CI

The [`reproducibility`](../.github/workflows/reproducibility.yml)
workflow rebuilds the `x86_64-unknown-linux-musl` target twice from
the same commit — same `SOURCE_DATE_EPOCH`, same container image,
but with all source-file mtimes shuffled between builds — and
requires the binaries to be byte-identical. It runs weekly
(Tuesdays 04:00 UTC) and on demand (`workflow_dispatch`); both
builds and their hashes are uploaded as artifacts so a mismatch can
be triaged offline. Until the build has a verified-green streak the
job is non-blocking (`continue-on-error`); after that it gates.

Until the job gates, third-party verification per the steps above
remains the canonical check.

## See also

- [Threat model](threat-model.md) — how reproducibility fits into the
  overall supply-chain threat picture.
- [Code signing](code-signing.md) — release artifact signing.
- [`ci/install.sh`](../ci/install.sh) — dependency build instructions.
