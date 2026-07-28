# 20 — Documentation site

**Priority**: P2
**Status**: specified

## Problem

enprot has docs.rs (auto-generated Rust API docs) and a comprehensive
README. No dedicated user-facing documentation site. Cookbooks,
comparison tables, and tutorials live scattered.

## Goal

Single documentation site at `https://engyon.github.io/enprot/` with:

- **Getting started** (5-minute path for new users)
- **Concepts** (EPT markup, capability model, chain anchors, CAS)
- **Cookbooks** (TODO 04 collection)
- **Reference** (CLI, library API, wire format)
- **Architecture** (positioning, comparison, Confium integration)
- **Migration guides** (TODO 23)

## Approach: mdBook + GitHub Pages

Confium uses `sites/` (likely mdBook too). Mirror the pattern.

### Site structure

```
docs-site/
  book.toml
  src/
    SUMMARY.md          # navigation
    README.md           # landing
    getting-started.md
    concepts/
      ept-markup.md
      capability-model.md
      chain-anchors.md
      cas.md
    cookbooks/
      collaborative-editing.md
      supply-chain.md
      classified-documents.md
    reference/
      cli.md
      library.md
      wire-format.md
    architecture/
      positioning.md
      confium-integration.md
    migration/
      from-git-crypt.md
      from-sops.md
      from-sigstore.md
```

### Build

```sh
mdbook build docs-site/
# outputs docs-site/book/
```

GitHub Actions:

```yaml
name: docs-site
on:
  push:
    branches: [main]
    paths: ['docs-site/**']
  workflow_dispatch: {}

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - run: cargo install mdbook
      - run: mdbook build docs-site
      - uses: actions/upload-pages-artifact@v3
        with:
          path: docs-site/book
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
    steps:
      - uses: actions/deploy-pages@v4
```

### Cross-linking

- README links to docs site for details
- docs.rs API docs link to docs site for concepts
- docs site links to RSD spec for normative definition

## What this is NOT

- A replacement for README. README stays as the repo landing page.
- Auto-generated API docs. docs.rs already does that.

## Acceptance criteria

- [ ] `docs-site/` directory with mdBook structure
- [ ] All TODO.completion/04 cookbooks migrated to site
- [ ] Site deployed to GitHub Pages
- [ ] Custom domain (optional): `docs.enprot.org`
- [ ] Search functionality (mdbook-pagetoc)

## Cross-references

- [[03-readme-positioning]] — README is the entry; site is the depth
- [[04-cookbooks]] — content source
