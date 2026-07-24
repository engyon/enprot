# 19 — KEY cannot contain commas when provided via CLI

## Problem

`-k Agent_007=a,ZFslw3` is ambiguous: is `ZFslw3` part of the password, or
a second `WORD=PASSWORD` pair without the `=`? Today enprot splits on
comma, so this becomes `(Agent_007, "a")` and `("ZFslw3", "")` — the
second one is rejected.

A password containing a comma has no escape hatch.

## Approach

Drop the comma-split. Each `-k` occurrence provides exactly one
`WORD=PASSWORD` pair. Multiple pairs require multiple `-k` flags.

This is the option-1 path from the issue. It's a small breaking change
(most usage already uses one `-k` per pair) but unambiguous and matches
what most modern CLIs do.

### Concrete changes

- `src/lib.rs::Cli::password`: remove `value_delimiter = ','`. Each
  invocation of `-k` is one element of the `Vec<(String, String)>`.
- `parse_word_password` value_parser stays the same (validates one
  `WORD=PASSWORD` form per element).
- Update `tests/cli/*.rs` invocations that used comma-separated values:
  - `-k Agent_007=a,GEHEIM=b` → `-k Agent_007=a -k GEHEIM=b`
  - `-k word=pass,with,commas` (hypothetical) now works as written.
- README.adoc: replace any comma-separated `-k` examples.

### Backward compatibility

`-k a=b,c=d` will fail (no `=` in `c=d` half → value_parser rejects). The
error message tells the user to use two `-k` flags. Acceptable break.

Existing golden files are unaffected (they encrypt content; the
invocation that produced them isn't checked into the repo).

## Verification

```
cargo test
cargo run -- --help | grep -A1 '.key>'   # confirm help still shows WORD=PASSWORD
```

Manual:

```
cargo run -- sample/test.ept -e Agent_007 -k 'Agent_007=p,ass'   # password with comma
```

must succeed (previously rejected).

Closes #19.

## Rollback

Re-add `value_delimiter = ','` to the password arg.
