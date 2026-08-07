# 46 — Cross-platform CI matrix expansion

**Priority**: P2
**Status**: specified

## Problem

CI tests on x86_64 only:
- ubuntu-latest (x86_64)
- macos-latest (x86_64 in CI terms, though Apple Silicon runners exist)
- windows-latest (x86_64)

Missing:
- **macOS aarch64** (Apple Silicon, the dominant macOS today).
- **Linux aarch64** (Raspberry Pi, AWS Graviton, most cloud ARM).
- **Windows aarch64** (emerging; Surface Pro X, ARM laptops).

Native aarch64 testing catches:
- Endianness bugs in hand-rolled binary parsers.
- Alignment assumptions (`mem::size_of::<T>()` differs).
- libc/libc++ ABI differences (musl vs glibc on ARM).
- Code-signing issues (macOS notarisation on arm64).

## Goals

- CI matrix includes `macos-14` (arm64), `ubuntu-24.04-arm` (or
  equivalent), and Windows arm64 once GitHub Actions supports it.
- Botan + librnp cross-compile / pre-built for each new target.
- Native aarch64 binaries are part of the release artifact set.

## Design

### Matrix expansion

```yaml
# .github/workflows/tests.yml
strategy:
  matrix:
    include:
      - { os: ubuntu-latest,  rust: stable,  arch: x86_64 }
      - { os: ubuntu-latest,  rust: beta,    arch: x86_64 }
      - { os: ubuntu-latest,  rust: '1.88',  arch: x86_64 }
      - { os: ubuntu-24.04-arm, rust: stable, arch: aarch64 }   # NEW
      - { os: macos-latest,   rust: stable,  arch: x86_64 }
      - { os: macos-14,       rust: stable,  arch: aarch64 }    # NEW
      - { os: windows-latest, rust: stable,  arch: x86_64 }
      - { os: windows-latest, rust: '1.88',  arch: x86_64 }
      # Windows arm64 deferred until GHA runners exist.
```

### Dependency story

| Target | Botan source | librnp source |
|---|---|---|
| Linux x86_64 | apt / vendored | apt / vendored |
| Linux aarch64 | apt / vendored | apt / vendored |
| macOS x86_64 | brew | brew / vendored |
| macOS aarch64 | brew | brew / vendored |

The existing `ci/install.sh` already handles Linux; extend it to
detect `aarch64` and install the right packages.

### Release artifacts

The deploy workflow (`deploy.yml`) currently builds 6 targets. Add:

| New target | Notes |
|---|---|
| `aarch64-unknown-linux-musl` | Static musl; AWS Graviton friendly |
| `aarch64-apple-darwin` | Universal binary option (lipo with x86_64) |

For macOS, consider shipping a **universal binary** (lipo of x86_64 + arm64):

```sh
lipo -create -output enprot target/x86_64-apple-darwin/release/enprot \
                          target/aarch64-apple-darwin/release/enprot
```

This gives users one binary that works on both Mac architectures.

## Implementation plan

1. Add `macos-14` (arm64) to the test matrix.
2. Verify Botan + librnp install on macOS arm64 (may need
   Homebrew path tweaks).
3. Add `ubuntu-24.04-arm` (or self-hosted runner) to the matrix.
4. Extend `deploy.yml` to produce arm64 binaries.
5. Optionally: produce a macOS universal binary via `lipo`.
6. Document the new artifacts in `docs/release-workflow.md`.

## Test plan

- [ ] `macos-14` job passes all tests.
- [ ] `ubuntu-*-arm` job passes all tests.
- [ ] Release workflow produces arm64 artifacts for both Linux + macOS.
- [ ] The macOS universal binary runs on both x86_64 + arm64 Macs.

## Out of scope

- Windows arm64 (GHA doesn't have native arm64 Windows runners yet).
- Cross-compilation from x86_64 to arm64 in CI (use native runners).
- iOS / Android (covered separately in TODO #47).
