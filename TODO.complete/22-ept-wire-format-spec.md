# 22 — EPT wire-format spec (JSON Schema)

**Priority**: P1
**Status**: specified

## Problem

EPT files are text. The format is documented in `README.md` + `docs/schemas/` as prose. Tooling (validators, LSP, third-party parsers) needs a machine-readable spec.

## Goals

- JSON Schema for the EPT wire format.
- Versioned (`docs/schemas/ept-wire-format-v1.json`).
- Used as input to [21-rsd-spec-conformance] for negative-test generation.
- Consumable by external validators (e.g., a future `enprot validate file.ept` that flags spec violations).

## Design

The wire format itself is text, not JSON — but its **parsed representation** (the AST) is what we schema-ify:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://engyon.org/schemas/ept-wire-format-v1.json",
  "title": "EPT file (v1)",
  "type": "object",
  "required": ["blocks"],
  "properties": {
    "separators": {
      "type": "object",
      "properties": {
        "left":  { "type": "string" },
        "right": { "type": "string" },
        "comment_leader": { "enum": ["//", "#", "--", "/*", ";"] }
      }
    },
    "blocks": {
      "type": "array",
      "items": { "$ref": "#/$defs/block" }
    }
  },
  "$defs": {
    "block": { "oneOf": [
      { "type": "object", "required": ["kind", "word", "body"],
        "properties": {
          "kind": { "enum": ["begin_end", "encrypted", "stored"] },
          "word": { "type": "string", "pattern": "^[A-Za-z0-9_]+$" },
          "body": { "type": "string" }
        }
      },
      { "type": "object", "required": ["kind"],
        "properties": { "kind": { "enum": ["plain", "data"] } }
      }
    ]}
  }
}
```

## Implementation plan

1. Write `docs/schemas/ept-wire-format-v1.json` from the existing prose spec.
2. Add `schemars::JsonSchema` derives to `etree::TextNode` and friends.
3. CI gate: the hand-written JSON Schema must match the schemars-generated one.
4. Add `enprot inspect --validate-schema` mode that flags deviations.

## Test plan

- [ ] All `sample/*.ept` files validate against the schema.
- [ ] Schema is internally consistent (no unresolved `$ref`s).
- [ ] `jsonschema` validator (any language) accepts the schema.

## Out of scope

- Non-JSON formats (RelaxNG, DTD). JSON Schema is the most common.
- Backwards-compat with EPT v0 (none exists; v1 is the first).
