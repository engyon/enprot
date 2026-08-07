# 35 — Streaming transform + write

**Priority**: P1
**Status**: specified (continuation of #05)

## Problem

`src/etree/streaming.rs` ships a streaming **parser**
(`Parser<R: BufRead> → ParseEvent`). The transform and write steps
still require the full `TextTree` in memory:

```rust
// src/cli/pipeline.rs (current)
let tree_in = etree::parse(reader_in, paops)?;           // ← full tree
let tree_out = etree::transform(&tree_in, paops)?;       // ← full tree
etree::tree_write(&mut writer_out, &tree_out, paops)?;   // ← full tree
```

Peak RSS for a 50 MB source file with several encrypted segments
hits ~150 MB. Multi-GB logs are unusable.

The streaming parser exists but has no consumer — you can build a
`Parser`, but you can't transform its output without first
collecting it into a tree.

## Goals

- `StreamingTransformer<R, W>` that consumes `ParseEvent`s from a
  `Parser<R>` and emits `WriteEvent`s to a `WriteSink<W>`.
- Peak RSS for a 1 GB file is `O(largest-block)`, not `O(file-size)`.
- The existing `parse → transform → tree_write` API stays available
  for callers that need the full tree (e.g. `inspect`).
- Byte-identical output between streaming and in-memory paths
  (verified by a property test).
- A `--streaming` CLI flag opts into the streaming path; default
  stays in-memory until streaming is battle-tested.

## Design

### WriteEvent

```rust
// src/etree/streaming.rs (extended)
#[derive(Debug, Clone)]
pub enum WriteEvent {
    /// Emit text verbatim (Plain bytes from the input).
    Plain(String),
    /// Emit a BEGIN/STORED/ENCRYPTED/etc. directive header.
    Directive { line: String },
    /// Emit a chunk of base64-encoded DATA.
    DataChunk(String),
    /// Emit an END directive.
    End { keyw: String },
    /// Flush the output writer.
    Flush,
}
```

### StreamingTransformer

```rust
pub struct StreamingTransformer<R: BufRead, W: Write> {
    parser: Parser<R>,
    sink: WriteSink<W>,
    // Per-block state. The transformer buffers one block at a time
    // (BEGIN ... END). When the END arrives, it applies the transform
    // to the buffered block and emits the transformed events.
    block_buffer: Option<BlockBuffer>,
    paops: ParseOps,
}

struct BlockBuffer {
    keyw: String,
    depth: usize,
    children: Vec<ParseEvent>,   // buffered children of the current block
    extfields: BTreeMap<String, String>,
}

impl<R: BufRead, W: Write> StreamingTransformer<R, W> {
    pub fn new(parser: Parser<R>, sink: WriteSink<W>, paops: ParseOps) -> Self { /* ... */ }

    /// Drive the transformer to completion. Pulls events from the
    /// parser, applies transforms, pushes events to the sink.
    pub fn run(mut self) -> Result<()> {
        while let Some(event) = self.parser.next_event()? {
            self.handle_event(event)?;
        }
        Ok(())
    }

    fn handle_event(&mut self, event: ParseEvent) -> Result<()> {
        match event {
            ParseEvent::Plain(s) => {
                // Outside any block: emit immediately (no transform needed).
                self.sink.emit(WriteEvent::Plain(s))?;
            }
            ParseEvent::BeginBlock { keyw, .. } => {
                // Start buffering block children.
                self.block_buffer = Some(BlockBuffer::new(keyw));
            }
            ParseEvent::EndBlock { .. } => {
                // Apply transform to the buffered block, then emit.
                if let Some(buf) = self.block_buffer.take() {
                    let transformed = transform_block(buf, &mut self.paops)?;
                    for evt in transformed {
                        self.sink.emit(evt)?;
                    }
                }
            }
            other => {
                // Data, Extfield, etc.: buffer if inside a block, else emit.
                if let Some(buf) = &mut self.block_buffer {
                    buf.children.push(other);
                } else {
                    self.sink.emit(WriteEvent::from_parse(other))?;
                }
            }
        }
        Ok(())
    }
}
```

### WriteSink

```rust
pub struct WriteSink<W: Write> {
    writer: W,
    data_line_width: usize,  // base64 line width (default 76)
}

impl<W: Write> WriteSink<W> {
    pub fn emit(&mut self, event: WriteEvent) -> Result<()> {
        match event {
            WriteEvent::Plain(s) => self.writer.write_all(s.as_bytes())?,
            WriteEvent::Directive { line } => {
                self.writer.write_all(b"// <( ")?;
                self.writer.write_all(line.as_bytes())?;
                self.writer.write_all(b" )>\n")?;
            }
            WriteEvent::DataChunk(chunk) => {
                self.writer.write_all(b"// <( DATA ")?;
                self.writer.write_all(chunk.as_bytes())?;
                self.writer.write_all(b" )>\n")?;
            }
            WriteEvent::End { keyw } => {
                writeln!(self.writer, "// <( END {keyw} )>")?;
            }
            WriteEvent::Flush => self.writer.flush()?,
        }
        Ok(())
    }
}
```

### Bounded memory

The transformer holds at most one block buffer at a time. For a
typical EPT file, the largest block is < 1 MB. The DATA chunks for
encrypted segments are streamed in fixed-size pieces (default 48
bytes per DATA line, matching the existing wire format), so even a
1 GB ciphertext doesn't blow memory.

The one exception is `tree_to_blob` for ENCRYPT operations — the
plaintext must be serialized into a single blob before encryption.
That blob is bounded by the block size, not the file size.

### CLI integration

```rust
// src/cli/pipeline.rs
if common.streaming {
    let parser = Parser::new(reader_in, separators);
    let sink = WriteSink::new(writer_out);
    let transformer = StreamingTransformer::new(parser, sink, paops);
    transformer.run()?;
} else {
    // existing in-memory path
}
```

## Implementation plan

1. Add `WriteEvent` + `WriteSink<W>` to `src/etree/streaming.rs`.
2. Implement `StreamingTransformer` with single-block buffering.
3. Add `transform_block` that applies the same logic as
   `etree::transform_begin_end` but on a buffered `BlockBuffer`.
4. Add `--streaming` flag to `CommonArgs`.
5. Wire the streaming path in `pipeline::process_one_file`.
6. Property test: streaming output == in-memory output for the same input.
7. Benchmark: peak RSS on a 1 GB synthetic file is < 200 MB.

## Test plan

- [ ] Byte-identical output vs in-memory path (property test, 256 cases).
- [ ] Peak RSS on 100 MB file is < 50 MB (vs ~300 MB in-memory).
- [ ] All existing transform tests pass on the streaming path.
- [ ] `--streaming` flag is opt-in; default stays in-memory.

## Out of scope

- Streaming across multiple files (covered by #04 parallel).
- Streaming with `--anchor` (requires full-file payload hash; inherently non-streaming).
- A async streaming variant (defer until a use case appears).
