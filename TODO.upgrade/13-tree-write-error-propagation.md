# 13 — Propagate writer errors in tree_write

## Goal

`etree::tree_write` uses `writeln!(outw, ...).unwrap()` on every write.
On a real failure (disk full, broken pipe, EPIPE), the binary panics
instead of returning the error to the caller. Fix.

## Files

- `src/etree.rs`

## Approach

Change `tree_write` to return `Result<()>` and propagate IO errors. The
single caller in `lib.rs::app_main` already runs in a context that can
report a top-level error and exit.

The shape:

```rust
pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) -> Result<()> {
    for elem in text {
        match elem {
            TextNode::Plain(line) => writeln!(outw, "{}", line)?,
            TextNode::BeginEnd { keyw, txt } => {
                writeln!(outw, "{} BEGIN {} {}", paops.left_sep, keyw, paops.right_sep)?;
                paops.level += 1;
                tree_write(outw, txt, paops)?;
                paops.level -= 1;
                writeln!(outw, "{} END {} {}", paops.left_sep, keyw, paops.right_sep)?;
            }
            // ... etc.
        }
    }
    Ok(())
}
```

`utils::base64_encode(...).unwrap()` inside the `Data` arm returns our
`Result<String>`, so use `?` there too.

The internal helper `tree_to_blob` also calls `tree_write`; switch its
signature to match.

## Verification

```
cargo test
```

Add a test that writes to a `Cursor<Vec<u8>>` (already done implicitly by
`tree_to_blob` in existing tests).

## Rollback

Revert the function signatures; the `unwrap` shape restores trivially.
