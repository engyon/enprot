# 21 — RSD spec conformance test suite

**Priority**: P0
**Status**: specified

## Problem

The Ribose Standard for Engyon Protected Text (RSD 12001) is the spec. enprot implements it. There is no published conformance suite — implementers of other EPT parsers cannot verify they match enprot, and refactors of enprot itself silently drift from the spec.

## Goals

- `tests/rsd-conformance/` directory with one `.ept` file per RSD spec rule, plus expected behavior.
- CI job runs the suite; any drift fails the build.
- The suite is reusable by third-party implementers (separate crate / language-agnostic JSON manifest).

## Design

```
tests/rsd-conformance/
├── manifest.json          # rule → fixture → expected-behavior
├── fixtures/
│   ├── 01-basic-begin-end.ept
│   ├── 02-nested-blocks.ept
│   ├── 03-stored-pointer.ept
│   ├── 04-encrypted-inline.ept
│   ├── 05-immutable-block.ept
│   ├── 06-mutable-block.ept
│   ├── 07-chain-anchor.ept
│   ├── 08-conflict-block.ept
│   ├── 09-include-directive.ept
│   ├── 10-data-multiline.ept
│   ├── 11-alt-separators-hash.ept
│   ├── 12-alt-separators-dash.ept
│   ├── 13-extfields-pbkdf.ept
│   ├── 14-extfields-cipher.ept
│   ├── 15-extfields-recipient.ept
│   ├── 16-immutable-with-stored.ept
│   ├── 17-malformed-mismatched-end.ept         # negative
│   ├── 18-malformed-unterminated-begin.ept      # negative
│   └── 19-malformed-bad-base64.ept              # negative
└── run.rs                  # tests/conformance.rs consumes the manifest
```

`manifest.json` schema:

```json
{
  "fixtures": [
    {
      "id": "01-basic-begin-end",
      "rule": "RSD §3.1",
      "input": "fixtures/01-basic-begin-end.ept",
      "expected": {
        "parse": "ok",
        "blocks": [
          { "kind": "begin_end", "word": "AGENT_007", "body_length": 12 }
        ]
      }
    },
    {
      "id": "17-malformed-mismatched-end",
      "rule": "RSD §3.4",
      "input": "fixtures/17-malformed-mismatched-end.ept",
      "expected": { "parse": "error", "error_kind": "MismatchedEnd" }
    }
  ]
}
```

## Implementation plan

1. Read RSD 12001 (latest revision from riboseinc/rsd-engyon-syntax).
2. Extract one positive and one negative fixture per rule.
3. Build the manifest + Rust harness that consumes it.
4. Add `tests/conformance.rs` that runs every fixture through `etree::parse()` and asserts the expected outcome.
5. Publish the manifest as `docs/schemas/rsd-conformance-v1.json` so third parties can reuse.

## Test plan

- [ ] Every fixture passes (or fails as expected).
- [ ] Adding a new RSD spec section adds one new fixture.

## Out of scope

- Translating the suite into a language-agnostic harness that third-party implementers can import (separate packaging TODO).
- Performance assertions (covered by `benches/`).
