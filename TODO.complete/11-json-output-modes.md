# 11 — JSON output modes for `inspect` / `list` / `status`

**Priority**: P1
**Status**: specified

## Problem

`enprot inspect file.ept` prints human-readable prose. Tools (CI scripts, dashboards, editor extensions) need machine-readable output. Today they have to regex-scrape the prose, which is brittle and loses structured fields.

## Goals

- `--json` flag on `inspect`, `list`, `status`, `conflicts`, `manifest`.
- Stable JSON schema (semver-guaranteed) documented at `docs/schemas/`.
- `--json` and `--json=pretty` for human vs. piped output.

## Design

```rust
#[derive(Serialize, JsonSchema)]
pub struct InspectReport {
    pub file: String,
    pub size_bytes: u64,
    pub blocks: Vec<BlockSummary>,
    pub chain_anchors: Vec<AnchorSummary>,
    pub signatures: Vec<SignatureSummary>,
    pub version: &'static str,  // schema version (separate from crate version)
}

#[derive(Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockSummary {
    Plain { length: usize },
    Encrypted { word: String, cipher: String, pbkdf: String, size: usize },
    Stored { word: String, hash: String },
    Immutable { word: String },
    Chain { index: u64, signers: Vec<String> },
}
```

CLI:

```sh
enprot inspect --json file.ept         # compact
enprot inspect --json=pretty file.ept  # pretty
enprot inspect --json=- file.ept | jq  # alias for compact
```

## Implementation plan

1. Add `schemars` to deps; derive `JsonSchema` for all report types.
2. Add `--json` global flag (clap arg).
3. Refactor each `run_*` to return a typed report struct; render either Human or JSON based on flag.
4. Generate `docs/schemas/inspect-v1.json` from the `schemars::schema_for!()` output; commit it; CI verifies it stays in sync.
5. Cookbook entry: `jq` recipes on inspect output.

## Test plan

- [ ] `enprot inspect --json file.ept | jq .blocks[0].kind` returns `"plain"`.
- [ ] Schema in `docs/schemas/inspect-v1.json` matches actual output.
- [ ] `--json` output is stable across patch releases (snapshot test).

## Out of scope

- Other output formats (YAML, TOML). `jq` + JSON covers most.
- Streaming/NDJSON output for huge reports.
