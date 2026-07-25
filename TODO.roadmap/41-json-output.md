# 41 — JSON output mode

**Priority**: P1
**Status**: specified (consolidated from TODO.finalize/07)

## Schema

Versioned: every output starts with `"$schema": "enprot/v1"`.

```rust
#[derive(Serialize)]
pub struct CapabilitiesOutput { pub capabilities: Vec<CapabilityDto> }

#[derive(Serialize)]
pub struct ListOutput { pub files: Vec<FileListing> }

#[derive(Serialize)]
pub struct VerifyChainOutput {
    pub ok: bool,
    pub anchors_total: usize,
    pub signers: Vec<String>,
    pub forks: Vec<ForkPoint>,
    pub errors: Vec<VerifyError>,
}
```

## Implementation

- Add `serde` + `serde_json` deps
- `src/output.rs`: typed output structs, `--format text|json` flag
- `text` remains default
- Snapshot tests for schema stability

## Acceptance criteria

- [ ] Every inspection subcommand supports `--format json`
- [ ] Output round-trips through typed structs
- [ ] Schemas documented in `docs/schemas/`
