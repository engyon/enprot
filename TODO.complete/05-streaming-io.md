# 05 — Streaming I/O for large files

**Priority**: P1
**Status**: specified

## Problem

`etree::parse()` reads the entire file into a `Vec<TextNode>`. A 50 MB source file with several encrypted segments hits ~150 MB peak RSS. For multi-GB logs or supply-chain manifests, enprot is unusable today.

## Goals

- `parse()` becomes a streaming iterator that emits `ParseEvent`s one at a time.
- `transform()` consumes the stream and emits `WriteEvent`s.
- `tree_write()` consumes the write stream and produces bytes.
- Peak RSS for a 1 GB file is O(largest-block) instead of O(file-size).

## Design

```rust
pub enum ParseEvent {
    Plain(String),
    BeginBlock { keyw: String, intent: BlockIntent },
    EndBlock { keyw: String },
    Encrypted { keyw: String, extfields: BTreeMap<String, String> },
    Stored { keyw: String, cas: String },
    Chain { extfields: BTreeMap<String, String> },
    Data(Vec<u8>),
}

pub struct Parser<R: BufRead> { reader: R, separators: Separators, stack: Vec<Frame> }

impl<R: BufRead> Iterator for Parser<R> {
    type Item = Result<ParseEvent>;
    // …
}
```

The transform step becomes a fold over the parser iterator. Buffering is bounded by the largest single block (BEGIN/END), which for typical use is < 1 MB.

## Implementation plan

1. Introduce `ParseEvent` + `Parser<R>` alongside the existing `parse()` function. Old API stays as `parse_to_tree()` for back-compat.
2. Introduce `Transform<C>` as a stateful fold over `ParseEvent → WriteEvent`.
3. Convert `process_one_file` to the streaming path.
4. Add a `--max-rss` flag that errors if estimated peak exceeds the limit.
5. Benchmark on 1 GB / 5 GB / 25 GB synthetic files.

## Test plan

- [ ] Streaming path produces identical bytes to `parse_to_tree` + `tree_write` for the same input.
- [ ] Peak RSS on a 1 GB file is < 200 MB.
- [ ] Round-trip (encrypt → decrypt) is byte-identical to in-memory path.

## Out of scope

- Concurrent streaming across multiple files (covered by [04-parallel-multi-file]).
- Custom block-size tuning — start with a fixed 1 MB buffer per block.
