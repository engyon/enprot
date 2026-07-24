# Refactoring: eliminate unreachable! in transform.rs

## Why

`src/etree/transform.rs` has three `unreachable!()` calls (lines 57,
116, 184). These are time bombs: if the parser ever produces a tree
shape we didn't anticipate (e.g., a `Stored` node where a `Data` was
expected inside `Encrypted`), the program panics instead of returning
an `Err`.

Per global rule: never trust "this can't happen". Either prove it via
the type system, or handle it gracefully. The current matches
probably can be tightened using `if let` + early return for the
unexpected case, returning `Error::msg(...)` with the actual node.

## Scope

1. Audit each `unreachable!()`:
   - Is the match truly exhaustive given invariants enforced by `parse()`?
   - If yes, document the invariant in a comment so the reader knows why
   - If no, replace with an explicit `Err` returning a descriptive message
2. Property tests: deliberately feed malformed trees to `transform()`
   and assert it returns `Err`, never panics
3. Apply the same audit to `unreachable!` in `src/lib.rs:65`
   (`make_policy`)

## Out of scope

- Rewriting the parser to make the invariants type-enforced (much
  larger change; defer to a typed-tree rewrite)
- Eliminating `unwrap()` in test code (fine in tests)

## Acceptance criteria

- Zero `unreachable!()` in production code (or each is documented with
  the invariant it relies on)
- Property test covers malformed-tree input
- All existing tests still pass
