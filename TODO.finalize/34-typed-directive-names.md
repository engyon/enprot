# Refactoring: typed directive names

## Why

Directive names (`BEGIN`, `END`, `STORED`, `ENCRYPTED`, `DATA`,
`CHAIN`) are currently bare strings throughout the parser. That's
stringly-typed: typos compile, refactoring is grep-driven, and
exhaustiveness checks don't work.

The `Command` enum in `etree::mod.rs` already exists for parse-time
dispatch; let's add an enum for serialization-time too, and make the
wire format derive from it. This is OCP-friendly: adding a new
directive type is one enum variant + one match arm per consumer.

## Scope

1. New enum `Directive` in `src/etree/mod.rs`:
   ```rust
   pub enum Directive {
       Begin, End, Stored, Encrypted, Data, Chain, Conflict, Include
   }
   impl Directive {
       pub fn keyword(&self) -> &'static str { ... }       // "BEGIN", etc.
       pub fn from_keyword(kw: &str) -> Option<Self> { ... }
   }
   ```
2. Replace all `&str` literals in parser and writer with `Directive`
   references
3. `TextNode` variants carry the `Directive` they correspond to (or
   use the existing variant structure as the source of truth — design
   choice)
4. Tests: round-trip; unknown keyword → `Err`, not silent skip
5. New directives added in TODOs 17, 19, 25 get enum entries from day one

## Out of scope

- Changing the wire format (keywords stay upper-case, etc.)
- Splitting `Command` (parse-time) and `Directive` (serial-time) into
  different types — they can be the same enum

## Acceptance criteria

- All directive keywords come from one enum
- Exhaustiveness checks work (adding a new variant forces all match
  arms to be updated)
- All existing tests still pass
