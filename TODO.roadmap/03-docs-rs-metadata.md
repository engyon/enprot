# 03 — docs.rs metadata + automated doc deployment

**Priority**: P1
**Status**: specified

## Problem

The `documentation` field in Cargo.toml points to a GitHub README, not
docs.rs. There's no docs.rs-specific metadata (feature flags, build
settings). The docs/ Astro site exists but isn't deployed automatically.

## Solution

### Cargo.toml metadata

```toml
[package.metadata.docs.rs]
# Build all features for docs.rs
all-features = true
# Botan needs pkg-config at build time
rustdoc-args = ["--cfg", "docsrs"]

[dependencies]
# Document feature-gated items
document-features = "0.2"  # optional: renders feature flags in docs
```

### GitHub Pages deployment for docs/ site

```yaml
# .github/workflows/deploy-docs.yml
name: Deploy Docs
on:
  push:
    branches: [main]
    paths: ['docs/**']
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - working-directory: docs
        run: |
          npm ci
          npm run build
      - uses: actions/upload-pages-artifact@v3
        with:
          path: docs/dist
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: github-pages
    steps:
      - uses: actions/deploy-pages@v4
```

### docs.rs landing page

Add crate-level rustdoc that renders well on docs.rs:

```rust
//! ![enprot](https://github.com/engyon/enprot/raw/main/docs/public/logo.svg)
//!
//! # enprot-core
//!
//! Confidentiality processor and capability ledger for text/source files.
//!
//! ## Quick links
//! - [Architecture](https://enprot.dev/docs/architecture)
//! - [Capability model](https://enprot.dev/docs/capability-model)
//! - [Chain DAG](https://enprot.dev/docs/chain-dag)
//! - [Examples](https://enprot.dev/docs/examples)
```

## Acceptance criteria

- [ ] `docs.rs/enprot-core` renders full API docs
- [ ] docs/ Astro site deploys to GitHub Pages on push to main
- [ ] Custom domain (enprot.dev) configured if available
