# TODO.complete — remaining work, prioritized

The authoritative list of enprot's outstanding work, organized by
area and priority. Each entry links to a detailed spec file in this
directory. The list is **MECE**: every work item lives in exactly
one TODO, every TODO has one priority + one area, and together they
cover everything from a 2026-07-31 audit of the codebase.

The earlier `TODO.completion/` directory is preserved as historical
context — items there that are still open have been promoted into
this directory with refreshed specs; items that shipped have been
removed from the active list and noted in `## Done` below.

## Status legend

- **specified**: TODO file only; no implementation yet
- **in-progress**: implementation started, on a branch
- **done**: shipped to main

## Priorities

- **P0** — blocks real use; correctness, security, or core-feature gap
- **P1** — high leverage for adoption, performance, or architecture
- **P2** — quality-of-life, additional platforms, polish
- **P3** — nice-to-have, deferred until P0/P1 lands

## Active TODOs

### Architecture (P0–P1)

| # | Title | Priority | Status |
|---|---|---|---|
| [01](01-ffi-pipeline-execution.md) | FFI: actually run the pipeline (not just validate JSON) | P0 | **done** (PR #212) |
| [02](02-typed-errors.md) | Replace `Error::Msg(String)` with typed variants | P0 | **partial** — FFI classifier migrated to typed match (PR #215); ~47% of callsites still use `Error::msg` |
| [03](03-sigstore-keyless-signing.md) | Sigstore keyless signing + verify path | P1 | **scaffold** — module + types land (PR #220); sigstore-rs integration pending |
| [04](04-parallel-multi-file.md) | Parallelize multi-file processing with rayon | P1 | **foundation** — `CryptoPolicy: Send + Sync` (PR #214); rayon integration pending |
| [05](05-streaming-io.md) | Streaming parse/transform/write for large files | P1 | specified |
| [06](06-cas-backends.md) | S3 + Rekor CAS backends | P1 | specified |
| [07](07-cli-rs-decomposition.md) | Decompose `src/cli.rs` into per-subcommand modules | P1 | specified |
| [08](08-property-invariants.md) | Property-based invariant tests (round-trip, identity) | P1 | **partial** — store/fetch + CAS invariants (PR #219); encrypt/decrypt + commutativity pending |
| [09](09-observability-tracing.md) | `tracing` subscriber + structured spans | P2 | specified |
| [10](10-dead-code-visibility-audit.md) | Dead code + module-visibility audit | P2 | specified |

### Tooling (P1–P2)

| # | Title | Priority | Status |
|---|---|---|---|
| [11](11-json-output-modes.md) | `--json` flag for `inspect` / `list` / `status` | P1 | **partial** — `inspect --format json` (PR #213); schemars-published JSON Schema pending |
| [12](12-ept-directive-grammar.md) | Formal pest grammar + machine-readable EPT spec | P1 | **scaffold** — grammar file lands (PR #220); pest-as-parser integration pending |
| [13](13-lsp-server.md) | LSP server (diagnostics, hover, goto-word) | P2 | specified |
| [14](14-wasm-build.md) | WASM build for browser/edge runtimes | P2 | specified |
| [15](15-marketplace-publish.md) | Publish VS Code extension + GitHub Action to Marketplaces | P2 | **done** (PR #217) |
| [16](16-ff-enprot-pipeline-ffi.md) | Standalone FFI subcommand runner (typed Config) | P2 | **foundation** — `RunConfig` typed dispatch (PR #218); serde derives pending |

### Distribution (P2–P3)

| # | Title | Priority | Status |
|---|---|---|---|
| [17](17-deb-rpm-packages.md) | Debian `.deb` + Fedora `.rpm` package specs | P2 | **done** (PR #217) — metadata in Cargo.toml; CI build step pending |
| [18](18-nixos-module.md) | NixOS module (`services.enprot.*`) | P3 | **done** (PR #217) |
| [19](19-snap-publish-fix.md) | Snap auto-publish (currently `continue-on-error`-style) | P2 | **done** (PR #217) — GitHub API download + jq asset resolution |
| [20](20-chocolatey-package.md) | Chocolatey package for Windows | P3 | **done** (PR #217) — nuspec + scripts; publish workflow pending |

### Specifications (P0–P1)

| # | Title | Priority | Status |
|---|---|---|---|
| [21](21-rsd-spec-conformance.md) | Ribose Standard for EPT — conformance test suite | P0 | specified |
| [22](22-ept-wire-format-spec.md) | Machine-readable EPT wire-format spec (JSON Schema) | P1 | **done** (PR #216) |
| [23](23-chain-anchor-spec.md) | CHAIN anchor format spec (verification rules, identity model) | P1 | **done** (PR #216) |
| [24](24-extfield-schema-spec.md) | Extfield (`pbkdf:`/`cipher:`/`recipient:`) schema | P1 | **done** (PR #216) |

### Capability model (P2)

| # | Title | Priority | Status |
|---|---|---|---|
| [25](25-capability-cli-surface.md) | Surface capability policy via CLI (`--cap-policy`, `--cap-attr`) | P2 | specified |

## Done (this session, 2026-07-30/31)

These items shipped during the multi-day adoption push and are no
longer active:

- FFI split into separate workspace member (#192 → `enprot-ffi/`)
- Deploy `.cargo/config.toml` duplicate-key fix (#190)
- Python bindings (`pyenprot`) + GitHub Action + pre-commit hook (#191)
- Node.js bindings (`@engyon/enprot`) + cookbook + SOPS importer (#193)
- VS Code extension (#194)
- Go bindings + Ruby bindings + AUR packages + Nix flake (#204)
- Release-plz working + crates.io publishing (enprot 0.5.13, enprot-ffi 0.5.11)
- Deploy tag-pattern fix for split-workspace tags (#209)
- Language bindings matrix: Python, Node, Go, Ruby — all live
- 14-recipe quickstart cookbook
- 8 dependabot dep bumps merged (clap_complete, clap_mangen, toml, criterion, GHA action bumps)

## Reading order for new contributors

1. [01-ffi-pipeline-execution](01-ffi-pipeline-execution.md) — biggest user-visible gap; concrete code work.
2. [02-typed-errors](02-typed-errors.md) — architectural foundation for many of the other items.
3. [03-sigstore-keyless-signing](03-sigstore-keyless-signing.md) — provenance story for CI.
4. [07-cli-rs-decomposition](07-cli-rs-decomposition.md) — make the codebase navigable.
5. [21-rsd-spec-conformance](21-rsd-spec-conformance.md) — single source of truth for behavior.

## Maintenance

- When you complete a TODO, change its status line to `done` and add
  the PR number under the title.
- New TODOs append to the end (no renumbering — keeps links stable).
- A TODO that proves to be the wrong shape gets superseded: rename to
  `XX-name.superseded.md`, write a one-paragraph explanation in the
  body, and add the replacement to the index.
