# 18 — Improve multi-file processing

## Problem

```
enprot -p output/ file.*           # produces outputfile.1, outputfile.2, …
enprot -p outputdir/ inputdir/*.ept # error: outputdir/inputdir/test.ept doesn't exist
```

The current code does `output = prefix.to_string() + &input`. There's no
concept of "output is a directory".

## Approach

Treat `prefix` as a directory when it ends with `/` **or** when the prefix
already exists as a directory. Output path is `prefix + basename(input)`.

Add a separate `--output-dir <DIR>` flag as the explicit, unambiguous
spelling. `-p`/`--prefix` keeps the prepend-string behavior for
backward compat, but auto-detects the directory case.

### Concrete rules

In the file-pairing loop, the output for input `path_in` is:

1. If `--output <FILE>` was paired with this input → use it as-is (current
   behavior; lets users override per-file).
2. Else if `--output-dir <DIR>` was given → `DIR + "/" + basename(path_in)`.
3. Else if `--prefix <PREFIX>` was given:
   - If `PREFIX` ends in `/` or `PREFIX` is an existing directory →
     `PREFIX (+ "/") + basename(path_in)`.
   - Else → `PREFIX + path_in` (current behavior).
4. Else if input is `-` → output is `-` (stdin/stdout passthrough).
5. Else → output = input (in-place).

This keeps `-p output/` working as users intuitively expect (directory
mode) and adds `--output-dir` for the explicit case.

### `--output-dir` vs `-p DIR/`

Both work. `--output-dir` is the documented form going forward; `-p DIR/`
is supported as a shortcut. Internally they feed the same pathing logic.

## Files

- `src/lib.rs` — add `output_dir: Option<PathBuf>` to `Cli`. Update
  `app_main`'s file-pairing loop with the new rules.
- `tests/cli/multi_file.rs` (new) — cover the five cases above.
- `tests/cli/misc.rs::output_multiple` — already covers case (1) via `-o`;
  leave alone.
- `README.adoc` — multi-file section update.

## Verification

```
mkdir -p /tmp/ept-out
cargo run -- encrypt Agent_007 --pbkdf legacy -k Agent_007=x \
    --output-dir /tmp/ept-out sample/test.ept sample/simple.ept
ls /tmp/ept-out    # should contain test.ept and simple.ept
```

## Rollback

Revert `src/lib.rs` and the new test file.
