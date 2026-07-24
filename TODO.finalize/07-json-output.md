# JSON output mode

## Why

Machine-readable output from `list`, `verify`, `verify-chain`,
`capabilities`, and other inspection commands. Critical for:

- Editor integrations (LSP servers, VS Code extensions)
- CI pipelines that need to parse results
- Programmatic access from other tools (the supply-chain manifest
  pipeline, build systems, audit dashboards)
- Snapshot testing

## Schema design

Schemas are typed structs in `src/output.rs`, serialized via `serde`.
One schema per command (MECE: each command has one JSON shape):

```rust
#[derive(Serialize)]
pub struct CapabilitiesOutput {
    pub capabilities: Vec<CapabilityDto>,
}

#[derive(Serialize)]
pub struct ListOutput {
    pub files: Vec<FileListing>,
}

#[derive(Serialize)]
pub struct FileListing {
    pub path: String,
    pub segments: Vec<SegmentListing>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SegmentListing {
    Plain { text: String },
    BeginEnd { word: String, children: Vec<SegmentListing> },
    Encrypted { word: String, cipher: String, pbkdf: String, storage: Storage },
    Stored { word: String, hash: String, kind: StoredKind },
    Chain { parents: Vec<String>, signer: String, timestamp: Option<String> },
}

#[derive(Serialize)]
pub struct VerifyChainOutput {
    pub ok: bool,
    pub anchors_total: usize,
    pub signers: Vec<String>,
    pub forks: Vec<ForkPoint>,
    pub errors: Vec<VerifyError>,
}
```

Versioned: every output starts with `"$schema": "enprot/v1"` so
consumers can detect format changes.

## Scope

1. New module `src/output.rs` with `serde`-derived structs and a
   `--format text|json` global flag
2. `serde` + `serde_json` deps
3. `text` remains default (human-friendly); `json` is opt-in
4. JSON schemas published in `docs/schemas/` for each command
5. Tests:
   - Every command's JSON output round-trips through
     `serde_json::from_str` back to the typed struct
   - Schema stability: snapshot tests in `tests/snapshots/`
   - Error path: malformed input produces well-formed JSON with an
     `error` field

## Out of scope

- Pretty-printing options (callers can pipe through `jq`)
- Streaming output (whole-response serialization is fine for v1)
- CSV / YAML output (defer; `jq` can convert)

## Compatibility

- `--format text` remains the default
- `--format json` is additive; existing scripts don't break
- Versioning: future `--format json2` for breaking changes; v1 stays
  available

## Acceptance criteria

- Every inspection subcommand supports `--format json`
- Output round-trips through the typed structs
- Schemas documented in `docs/schemas/`
- Snapshot tests pin the v1 shape
