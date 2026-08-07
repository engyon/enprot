# 55 — Zero-copy parsing

**Priority**: P3
**Status**: specified

## Problem

`etree::parse(reader, paops)` reads the entire file into `String`
and `Vec<u8>` allocations:

```rust
pub fn parse<R: BufRead>(mut reader: R, paops: &mut ParseOps) -> Result<TextTree> {
    let mut text = String::new();
    for line in reader.lines() {
        let line = line?;
        // ... line is owned; cloned into Plain nodes ...
    }
}
```

For a 100 MB file, that's ~100 MB of `String` allocations just for
the Plain nodes. Most of these bytes are never modified — they're
passed through to the output verbatim.

Zero-copy parsing borrows from the input instead of owning a copy.
Peak RSS drops from `O(file_size)` to `O(largest_block)`.

## Goals

- A `Parser` variant that borrows input bytes (lifetime-tied to the
  input buffer).
- The existing owning `Parser` stays available for callers that
  need owned output (CLI, FFI).
- Peak RSS for a 1 GB file is < 50 MB (vs ~1.5 GB today).
- No behavioral difference between owning and borrowing paths.

## Design

### Two parser variants

```rust
// Owning (current behavior)
pub fn parse<R: BufRead>(reader: R, paops: &mut ParseOps) -> Result<TextTree>;

// Borrowing (new)
pub fn parse_borrowed<'input, R: BufRead<'input>>(
    reader: R,
    paops: &mut ParseOps,
) -> Result<BorrowedTextTree<'input>>;
```

`BorrowedTextTree<'input>` holds `&'input str` slices into the
input buffer instead of owned `String`s.

### BorrowedTextTree

```rust
pub enum BorrowedTextNode<'input> {
    Plain(&'input str),
    BeginEnd {
        keyw: &'input str,
        txt: Vec<BorrowedTextNode<'input>>,
    },
    Encrypted {
        keyw: &'input str,
        txt: Vec<BorrowedTextNode<'input>>,
        extfields: BTreeMap<&'input str, &'input str>,
    },
    // ... other variants
}

pub type BorrowedTextTree<'input> = Vec<BorrowedTextNode<'input>>;
```

The lifetime `'input` ties the tree to the input buffer. Callers
that need to keep the tree around longer than the input must
explicitly call `.to_owned()` to convert to a `TextTree`.

### When to use which

| Caller | Use |
|---|---|
| CLI (`process_one_file`) | Owning — the output tree is built fresh by `transform` |
| `inspect` (display only) | Borrowing — read-only, no transform |
| `list` | Borrowing |
| `verify` | Borrowing (parse only, no transform) |
| Tests that compare trees | Owning — easier to construct expected values |
| FFI | Owning — C can't hold Rust lifetimes |

### Memory-mapped input

For very large files, the input buffer can be memory-mapped:

```rust
let file = memmap2::Mmap::map(&File::open(path)?)?;
let parser = BorrowedParser::from_bytes(&file);
let tree = parser.parse()?;
// tree borrows from `file` — no copy
```

This is the lowest-peak-RSS option. The OS pages the file in and
out as needed; the program sees only the bytes it actually touches.

### Limitations

- The borrow lifetime must outlive every derived reference. If the
  caller stores slices past the input's lifetime, the borrow
  checker rejects it.
- Transforms that modify content (encrypt, decrypt, store, fetch)
  can't be zero-copy — they produce new bytes. The borrow path
  only helps for read-only operations (`list`, `inspect`, `verify`).
- Memory-mapping doesn't work for pipes / stdin (need an in-memory
  buffer).

## Implementation plan

1. Add `BorrowedTextNode` + `BorrowedTextTree` types.
2. Implement `parse_borrowed` — share the directive-matching logic
   with `parse` via a generic helper.
3. Add `BorrowedTextTree::to_owned()` conversion.
4. Convert `list`/`inspect`/`verify` to use borrowed parsing.
5. Add memory-mapped input path via `memmap2` (behind a `mmap`
   feature).
6. Benchmark peak RSS on a 1 GB synthetic file.

## Test plan

- [ ] Borrowed parse produces identical tree shape to owning parse.
- [ ] Peak RSS on a 100 MB file is < 50 MB (borrowed + mmap).
- [ ] All `list`/`inspect`/`verify` tests pass unchanged.
- [ ] `cargo bench` shows borrowed parse is faster than owning parse.

## Out of scope

- Borrowing in `transform` — inherently produces new bytes; can't
  borrow from input.
- Borrowing in `tree_write` — writes are serialised to output; no
  benefit from borrowing.
- A streaming variant of borrowing (covered by #35 streaming transform).
