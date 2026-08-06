# TODO.complete — remaining work, prioritized

The authoritative list of enprot's outstanding work, organized by
area and priority. Each entry links to a detailed spec file in this
directory. The list is **MECE**: every work item lives in exactly
one TODO, every TODO has one priority + one area, and together they
cover everything from a 2026-07-31 audit of the codebase (refreshed
2026-08-06).

The earlier `TODO.completion/` directory is preserved as historical
context — items there that are still open have been promoted into
this directory with refreshed specs; items that shipped have been
removed from the active list and noted in `## Done` below.

## Status legend

- **specified**: TODO file only; no implementation yet
- **partial**: some implementation landed; remaining work tracked in the file
- **scaffold**: foundation code in place; main feature still pending
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
| [02](02-typed-errors.md) / [26](26-typed-errors-callsite-migration.md) | Typed errors: enum landed; ~106 callsites still use `Error::msg` | P0 | **partial** — variants + FFI shipped; callsite migration tracked in #26 |
| [03](03-sigstore-keyless-signing.md) / [32](32-sigstore-keyless-fulcro-rekor.md) | Sigstore keyless signing + verify path | P1 | **partial** — local Ed25519 path shipped; Fulcio+Rekor integration tracked in #32 |
| [04](04-parallel-multi-file.md) | Parallelize multi-file processing with scoped threads | P1 | **done** — `--jobs` flag shipped (#236); `CryptoPolicy: Send + Sync` (PR #214) |
| [05](05-streaming-io.md) | Streaming parse/transform/write for large files | P1 | **partial** — `ParseEvent` + `Parser<R>` shipped (`src/etree/streaming.rs`); streaming transform + write pending |
| [06](06-cas-backends.md) / [27](27-cas-backends-real.md) | S3 + IPFS + Rekor CAS backends | P1 | **scaffold** — `open_cas` dispatch + `MemoryCas` shipped; real backends tracked in #27 |
| [07](07-cli-rs-decomposition.md) / [29](29-cli-decomposition-finalize.md) | Decompose `src/cli.rs` into per-subcommand modules | P1 | **partial** — 9 modules extracted, mod.rs 3260→1220 lines (#236); clap-struct + helper split tracked in #29 |
| [08](08-property-invariants.md) | Property-based invariant tests (round-trip, identity) | P1 | **done** — store/fetch + CAS + encrypt/decrypt + idempotency + encrypt-store (PR #238) |
| [09](09-observability-tracing.md) / [31](31-tracing-instrumentation-expand.md) | `tracing` subscriber + structured spans | P2 | **partial** — foundation + 3 instrumented fns shipped; full coverage tracked in #31 |
| [10](10-dead-code-visibility-audit.md) | Dead code + module-visibility audit | P2 | specified |

### Tooling (P1–P2)

| # | Title | Priority | Status |
|---|---|---|---|
| [11](11-json-output-modes.md) | `--json` flag for `inspect` / `list` / `status` | P1 | **partial** — `inspect --format json` (PR #213); schemars-published JSON Schema pending |
| [12](12-ept-directive-grammar.md) | Formal pest grammar + machine-readable EPT spec | P1 | **scaffold** — grammar file lands (PR #220); pest-as-parser integration pending |
| [13](13-lsp-server.md) | LSP server (diagnostics, hover, goto-word) | P2 | **scaffold** — minimal server ships (#236-era); feature surface pending |
| [14](14-wasm-build.md) | WASM build for browser/edge runtimes | P2 | **scaffold** — feature flag exists; WASM-compatible crypto path pending |
| [15](15-marketplace-publish.md) | Publish VS Code extension + GitHub Action to Marketplaces | P2 | **done** (PR #217) |
| [16](16-ff-enprot-pipeline-ffi.md) | Standalone FFI subcommand runner (typed Config) | P2 | **partial** — `RunConfig` typed dispatch (PR #218, moved to `cli/pipeline.rs` in #236); serde derives pending |

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
| [21](21-rsd-spec-conformance.md) / [30](30-rsd-conformance-expand.md) | Ribose Standard for EPT — conformance test suite | P0 | **partial** — 5 fixtures shipped (PR #219); expand to ~25 fixtures tracked in #30 |
| [22](22-ept-wire-format-spec.md) | Machine-readable EPT wire-format spec (JSON Schema) | P1 | **done** (PR #216) |
| [23](23-chain-anchor-spec.md) | CHAIN anchor format spec (verification rules, identity model) | P1 | **done** (PR #216) |
| [24](24-extfield-schema-spec.md) | Extfield (`pbkdf:`/`cipher:`/`recipient:`) schema | P1 | **done** (PR #216) |

### Capability model (P2)

| # | Title | Priority | Status |
|---|---|---|---|
| [25](25-capability-cli-surface.md) / [28](28-capability-policy-cli-surface.md) | Surface capability policy via CLI (`--cap-policy`, `--cap-attr`) | P2 | **partial** — `enprot cap` introspection (PR #219); policy surface tracked in #28 |

## Done (2026-07-30 — 2026-08-06)

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
- **Stubs eliminated**: streaming parser, sigstore sign/verify, memory CAS (#236-era)
- **CLI decomposition Phase 1**: 9 modules extracted, mod.rs 3260→1220 lines (#236)
- **Windows CI fixed**: LNK1201 PDB race resolved via sequential enprot + enprot-ffi build (#237)
- **OHOS CI fixed**: cross-compile librnp + deps via new ci/build-rnp-ohos.sh; QEMU for dockerharmony verify (#237)
- **Property tests complete**: encrypt/decrypt/encrypt-store invariants (PR #238)

## Reading order for new contributors

1. [26-typed-errors-callsite-migration](26-typed-errors-callsite-migration.md) — concrete code work; mechanical; ~106 sites.
2. [29-cli-decomposition-finalize](29-cli-decomposition-finalize.md) — make the codebase navigable (post-#236).
3. [30-rsd-conformance-expand](30-rsd-conformance-expand.md) — single source of truth for behavior.
4. [31-tracing-instrumentation-expand](31-tracing-instrumentation-expand.md) — production observability.
5. [27-cas-backends-real](27-cas-backends-real.md) — supply-chain story.

## Maintenance

- When you complete a TODO, change its status line to `done` and add
  the PR number under the title.
- New TODOs append to the end (no renumbering — keeps links stable).
- A TODO that proves to be the wrong shape gets superseded: rename to
  `XX-name.superseded.md`, write a one-paragraph explanation in the
  body, and add the replacement to the index.
- **Split vs extend**: when a TODO grows beyond ~500 lines of spec,
  prefer splitting it (e.g. #02 → #02 + #26) over bloating the file.
  The original keeps the high-level design; the new one details the
  remaining work.
