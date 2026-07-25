# 04 — CI: MSRV + beta channel testing

**Priority**: P1
**Status**: specified

## Problem

CI tests on stable only. No MSRV (minimum supported Rust version)
verification. No beta-channel testing to catch breakage before it
reaches stable. parsanol-rs tests MSRV, stable, and beta.

## Solution

Add matrix dimensions to the test job:

```yaml
strategy:
  fail-fast: false
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    rust: [stable, beta, "1.85"]  # 1.85 = MSRV (edition 2024)
    exclude:
      - os: windows-latest
        rust: beta  # save CI minutes; beta on Windows is low-value
```

### MSRV pinning

Add `rust-version = "1.85"` to workspace Cargo.toml (already present
in the single-crate Cargo.toml). Verify with:

```sh
rustup install 1.85
cargo +1.85 build --workspace
cargo +1.85 test --workspace
```

### CI-quality badge

Update README badge to show MSRV:

```markdown
![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)
```

## Acceptance criteria

- [ ] CI tests on stable, beta, and 1.85
- [ ] MSRV breakage caught in CI before stable release
- [ ] CI badges in README
