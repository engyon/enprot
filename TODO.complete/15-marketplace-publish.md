# 15 — Marketplace publishing pipelines

**Priority**: P2
**Status**: specified

## Problem

VS Code extension and GitHub Action both ship as in-tree directories (`editors/vscode/`, `action/`) but neither has an automated publish pipeline. Releasing requires manual `vsce publish` / GitHub release steps.

## Goals

- Tag-driven publish for both:
  - `enprot-v0.5.X` tag → publish VS Code extension v0.5.X to Marketplace
  - `enprot-v0.5.X` tag → move `engyon/enprot-action@v0.5` major-minor tag
- Both gated on the Rust deploy having succeeded (binary must exist before action republishes).

## Design

### VS Code extension

```yaml
# .github/workflows/publish-vscode.yml
on:
  push:
    tags: ['enprot-v[0-9]*.[0-9]*.[0-9]*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - working-directory: editors/vscode
        run: |
          npm install
          npm run package
      - uses: JohnBil vsce-publish@v1
        with:
          pat: ${{ secrets.VSCE_PAT }}
          extensionFile: editors/vscode/enprot-*.vsix
```

### GitHub Action

```yaml
# .github/workflows/publish-action.yml
on:
  push:
    tags: ['enprot-v[0-9]*.[0-9]*.[0-9]*']
jobs:
  retag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          git tag -f v0.5 ${{ github.ref_name }}
          git tag -f v0 ${{ github.ref_name }}
          git push -f origin v0.5 v0
```

## Implementation plan

1. Acquire VSCE PAT (storage: `VSCE_PAT` secret).
2. Add `vscode:commitMessage`, `vscode:version` fields to extension package.json (auto-managed by vsce).
3. Add the two workflows.
4. Document in `editors/vscode/RELEASE.md` + `action/RELEASE.md`.

## Test plan

- [ ] First publish succeeds from a tag push.
- [ ] Updating a major-minor tag (`v0.5`) works.
- [ ] Rollback procedure documented.

## Out of scope

- OpenVSX publishing (alternative marketplace; revisit if Eclipse IDE users appear).
- Cross-platform VSIX validation (`vsce package` runs on Linux already).
