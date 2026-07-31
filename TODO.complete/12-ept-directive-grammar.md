# 12 — Formal EPT directive grammar

**Priority**: P1
**Status**: specified

## Problem

The EPT parser is hand-written in `src/etree/parse.rs`. The grammar is implicit in the code. New tooling (LSP, syntax highlighters, third-party parsers) cannot easily reuse the grammar — they'd have to reverse-engineer it from the code or port it by hand.

## Goals

- A formal grammar in `docs/schemas/ept.ebnf` (or `ept.pest`) that is the single source of truth.
- The Rust parser either is generated from this grammar (`pest`), or has a property-based test that asserts it matches the grammar.
- The grammar round-trips: every file in `sample/` parses successfully, and the parsed structure re-emits an equivalent file.

## Design (pest)

```pest
// docs/schemas/ept.pest
file = { SOI ~ line+ ~ EOI }
line = { directive ~ NL | plain }
directive = { ws? ~ comment_leader ~ ws? ~ "<(" ~ ws? ~ directive_body ~ ws? ~ ")>" }
comment_leader = { "//" | "#" | "--" | "/*" | ";" }
directive_body = { begin | end | encrypted | stored | data | chain | immutable | mutable }
begin       = { "BEGIN" ~ ws+ ~ word }
end         = { "END" ~ ws+ ~ word }
encrypted   = { "ENCRYPTED" ~ ws+ ~ word ~ extfield* }
stored      = { "STORED" ~ ws+ ~ word ~ ws+ ~ key_value }
data        = { "DATA" ~ ws+ ~ base64 }
word        = @{ ASCII_ALPHANUMERIC+ }
extfield    = { ws+ ~ key ~ "=" ~ value }
```

Adopt `pest` as the parser generator. Either:

1. **Replace** the hand-written parser with the pest one (cleaner, single source of truth).
2. **Keep both** — pest as the spec, hand-written for performance (current is ~5× faster on large files). Property test asserts the two agree on every input.

Option 1 is the model-driven choice; option 2 is pragmatic. Default to option 1 unless benchmarks show >2× slowdown.

## Implementation plan

1. Write `docs/schemas/ept.pest` (initial spec, no code changes).
2. Implement pest parser in `src/etree/pest_parser.rs`.
3. Add a feature flag `pest-parser` that switches `parse()` between hand-written and pest.
4. Benchmark both; pick option 1 or 2 based on results.
5. Generate bindings for other languages via `tree-sitter-ept` (separate TODO).

## Test plan

- [ ] Every file in `sample/` and `test-data/` parses.
- [ ] Property test: random pest-generated files round-trip through `parse → tree_write`.
- [ ] Benchmarks: pest parser within 2× of hand-written.

## Out of scope

- tree-sitter grammar for editor use ([13-lsp-server]).
- W3C XML-style formal validation.
