# 62 — Parser performance: fix O(N²) scaling

**Priority**: P1
**Status**: specified

## Problem

The benchmarks (TODO.roadmap/05) show the parser is superlinear:
4k segments ≈ 600ms, 32k ≈ 41s. That's ~15× per 8× input —
worse than O(N²).

## Root cause analysis

The `parse_begin` and `parse_end` functions use a stack-based
approach where the entire current text accumulator is swapped
into the stack frame on BEGIN and restored on END:

```rust
// parse_begin
pstack.push(Frame::BeginEnd {
    outer: std::mem::take(text),  // ← moves the entire Vec
});
// parse_end
*text = outer;  // ← moves back
text.push(node);
```

Each `std::mem::take` + restore is O(N) in the current text
length. For a file with N segments, the text grows linearly,
and each BEGIN/END pair does an O(N) copy — total O(N²).

The `tree_to_blob` function (used by the encrypt transform)
has a similar pattern: it serializes the tree by iterating
every node, including `Plain` nodes that can be very large.

## Solution

Two-part fix:

### Part 1: Avoid copying in parse_begin/parse_end

Instead of saving/restoring the entire text vector, use a
"depth marker" approach:

```rust
// On BEGIN: remember the current text length
let mark = text.len();
pstack.push(Frame::BeginEnd { keyw, mark });

// On END: split text at the mark
let inner: Vec<TextNode> = text.split_off(mark);
text.push(TextNode::BeginEnd { keyw, txt: inner });
```

`split_off` is O(N-k) where k is the mark position — still
linear, but the constant is much smaller (no full-Vec copy
into the stack frame and back). For deeply nested structures,
this reduces the total work significantly.

### Part 2: Tree-to-blob streaming

`tree_to_blob` currently builds a `Vec<u8>` by concatenating
every node's serialization. For large trees, this causes
multiple reallocations. Pre-sizing the output buffer based on
the tree's estimated size would reduce reallocation overhead.

## Acceptance criteria

- [ ] Benchmark 32k segments completes in < 5s (currently 41s)
- [ ] Benchmark 4k segments completes in < 100ms (currently 600ms)
- [ ] All existing tests pass (no wire-format change)
- [ ] Property tests (proptest) still pass (round-trip identity)
