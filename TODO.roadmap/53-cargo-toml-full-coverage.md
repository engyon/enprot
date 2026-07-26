# 53 — Cargo.toml full dependency coverage

**Priority**: P2
**Status**: specified

## Problem

`scm deps Cargo.toml` (TODO.roadmap/52) only reads the top-level
`[dependencies]` table. Real Cargo manifests have:

- `[dev-dependencies]` — test-only deps
- `[build-dependencies]` — build script deps
- `[target.'cfg(...)'.dependencies]` — platform-specific deps
- `[workspace.dependencies]` — workspace-inherited deps
- `[dependencies]` entries that reference workspace inheritance:
  `serde = { workspace = true }`

All of these affect the supply chain but are invisible to the
current parser. A vendor signing a manifest that omits build-deps
is attesting to an incomplete picture.

## Solution

Extend `scm::add_cargo_deps` to walk every dependency-bearing table
in the manifest. Tag each entry with its source so the manifest
records `# dep: serde=1.0 (deps)` vs `# dep: tempfile=3 (dev-deps)`
vs `# dep: cc=1.0 (build-deps)` vs `# dep: openssl=0.10 (target cfg(unix))`.

For workspace-inherited entries (`workspace = true`), emit a `# dep:
name=workspace` entry pointing at the workspace root's
`[workspace.dependencies]` definition — the actual version lives
there. The vendor should re-run `scm deps Cargo.toml` from the
workspace root to capture the resolved versions.

Sort order: alphabetical by (table_name, name) so the same manifest
produces byte-identical output across runs.

## Acceptance criteria

- [ ] `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
      all parsed and emitted with their source tag
- [ ] Target-conditional deps emitted with their cfg expression
- [ ] Workspace-inherited deps emit a `=workspace` placeholder
- [ ] Tests cover every table form
