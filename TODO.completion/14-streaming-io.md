# 14 — Streaming I/O for large files

**Priority**: P2
**Status**: specified (architectural refactor)

## Problem

enprot loads files entirely into memory. For a 50MB source file with
several encrypted segments, that's ~150MB peak RSS (file text +
parsed tree + CAS blobs). For multi-GB log files or database dumps
(the supply-chain manifest use case), enprot is unusable today.

The parser is the bottleneck — it builds the full `TextTree` before
any transform can run.

## Solution

### Phase 1: Streaming parser

Refactor `parse()` into an iterator over `ParseEvent`:

```rust
pub enum ParseEvent {
    Plain(String),
    BeginBlock { keyw: String, intent: BlockIntent },
    EndBlock { keyw: String },
    Encrypted { keyw: String, extfields: BTreeMap<String, String> },
    Stored { keyw: String, cas: String },
    Chain { extfields: BTreeMap<String, String> },
    Data(Vec<u8>),
    // ...
}

pub struct Parser<R: BufRead> {
    reader: R,
    separators: Separators,
    stack: Vec<Frame>,
}

impl<R: BufRead> Iterator for Parser<R> {
    type Item = Result<ParseEvent>;
    fn next(&mut self) -> Option<Self::Item> { ... }
}
```

Existing `parse()` becomes a thin wrapper that collects the iterator
into a `Vec<TextNode>`. Existing callers don't change.

### Phase 2: Streaming transform

`transform()` becomes `transform_stream()`:

```rust
pub fn transform_stream(
    parser: &mut impl Iterator<Item = Result<ParseEvent>>,
    sink: &mut impl Write,
    paops: &mut ParseOps,
) -> Result<()> { ... }
```

The transform emits the output as it consumes events. CAS
operations (encrypt, store) still need the full plaintext of a
WORD region — they buffer per-WORD, not the whole file.

### Phase 3: Streaming CAS

```rust
pub fn save_stream(reader: &mut impl Read, casdir: &Path) -> Result<String> {
    let mut hasher = Sha3_256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let hash = hex::encode(hasher.finalize());
    // ... write to CAS file
    Ok(hash)
}
```

Streaming hash → CAS for any blob size. Encrypt-streaming is
harder (AEAD modes need length upfront) but possible with chunked
AEAD.

## What this enables

- Supply-chain manifest for multi-GB source trees (TODO 04 Cookbook B)
- Audit-log signing without loading the log into RAM
- CAS for arbitrary file sizes (no upper bound)

## What this costs

- API surface: a second `transform_stream` alongside `transform`
- Complexity: each transform needs both eager and lazy variants
- Memory: only marginally smaller for typical (small) files; big
  win only for large files

## Acceptance criteria

- [ ] `Parser<R: BufRead>` iterator implemented
- [ ] `parse()` reimplemented as a collect() over the iterator
- [ ] `transform_stream()` added; existing `transform()` unchanged
- [ ] `cas::save_stream()` for arbitrary-size blobs
- [ ] Benchmark: 1GB file processed without OOM
- [ ] Tests: streaming output byte-identical to eager output

## Cross-references

- TODO.roadmap/05 — benchmarks (would benefit from streaming)
- [[15-cas-backend-trait]] — pluggable CAS for large blobs
