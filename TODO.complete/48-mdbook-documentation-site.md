# 48 — mdbook documentation site

**Priority**: P2
**Status**: specified

## Problem

`docs/` contains ~15 Markdown + AsciiDoc files (architecture, FIPS,
code-signing, release-workflow, fuzzing, OHOS porting, migration,
cookbook). They're flat files, not a navigable site:

- No table of contents.
- No cross-linking.
- No search.
- No version selector.
- Inconsistent formats (Markdown + AsciiDoc mix).

Users who want to learn enprot land on the GitHub README, not a
proper documentation site. Adoption suffers.

## Goals

- A published documentation site at `https://enprot.dev/docs/`
  (or `engyon.github.io/enprot`).
- Single source of truth: `docs/` Markdown files become the site;
  no duplicate content.
- Search, version selector, dark mode.
- Auto-deploys on push to main via GitHub Pages.

## Goals (non-goals)

- Marketing site (separate concern).
- Interactive playground (deferred).
- API docs (rustdoc, served separately).

## Design

### Tool choice: mdbook

[mdbook](https://rust-lang.github.io/mdBook/) is the standard for
Rust-ecosystem docs (used by the Rust Reference, the Async Book,
the Edition Guide). Reasons:

- Native Markdown input (matches existing `docs/*.md`).
- Rust-affiliated (built in Rust, theme matches rust-lang.org).
- GitHub Actions deployment is well-trodden.
- Lightweight; no React/Node toolchain.

### Site structure

```
docs/                          # source of truth
├── book.toml                  # mdbook config
├── src/
│   ├── SUMMARY.md             # table of contents (mdbook convention)
│   ├── introduction.md        # redirect to README content
│   ├── getting-started/
│   │   ├── installation.md
│   │   ├── first-encrypt.md
│   │   └── ...
│   ├── guides/
│   │   ├── architecture.md    ← symlinked from docs/architecture.md
│   │   ├── fips.md            ← symlinked from docs/fips.md
│   │   ├── code-signing.md
│   │   └── ...
│   ├── reference/
│   │   ├── wire-format.md     ← symlinked from docs/schemas/ept-wire-format-v1.md
│   │   ├── chain-anchor.md
│   │   └── ...
│   ├── cookbook/
│   │   └── (existing cookbook recipes)
│   └── ...
└── theme/                     # custom CSS/JS for branding
```

### SUMMARY.md (the navigation)

```markdown
# Table of Contents

[Introduction](./introduction.md)

# Getting Started
- [Installation](./getting-started/installation.md)
- [Your first encrypt](./getting-started/first-encrypt.md)

# Guides
- [Architecture](./guides/architecture.md)
- [FIPS mode](./guides/fips.md)
- [Code signing](./guides/code-signing.md)

# Reference
- [EPT wire format](./reference/wire-format.md)
- [CHAIN anchor format](./reference/chain-anchor.md)
- [Extfield schema](./reference/extfield-schema.md)

# Cookbook
- [14 quickstart recipes](./cookbook/index.md)
```

### CI deployment

```yaml
# .github/workflows/docs.yml
name: docs
on:
  push:
    branches: [main]
    paths: ['docs/**', '.github/workflows/docs.yml']

jobs:
  build-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: peaceiris/actions-mdbook@v2
        with:
          mdbook-version: '0.4.40'
      - run: mdbook build docs/
      - uses: peaceiris/actions-gh-pages@v4
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: docs/book/
```

The site publishes to the `gh-pages` branch automatically.

### Markdown/AsciiDoc unification

Current docs are a mix of `.md` and `.adoc` (AsciiDoc). Pick
Markdown as the canonical format and convert AsciiDoc files
(asciidoctor has a `-b docbook5` then `pandoc` to Markdown path).

## Implementation plan

1. Audit `docs/` and convert AsciiDoc → Markdown where needed.
2. Add `docs/book.toml` + `docs/src/SUMMARY.md`.
3. Symlink existing Markdown files into the `src/` structure.
4. Add `docs.yml` workflow.
5. Configure GitHub Pages to serve from `gh-pages` branch.
6. Set up a custom domain (optional).
7. Document the docs workflow in CONTRIBUTING.md.

## Test plan

- [ ] `mdbook build docs/` produces valid HTML.
- [ ] All internal links work.
- [ ] Search returns relevant results.
- [ ] Site auto-deploys on push to main.
- [ ] Existing docs/README.md and docs/architecture.md are unchanged.

## Out of scope

- Multilingual docs (i18n) — defer until non-English demand exists.
- Interactive examples (e.g. embedded playground).
- Paid hosting (Cloudflare, Netlify) — GitHub Pages is free.
