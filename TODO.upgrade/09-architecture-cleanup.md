# 09 — Architecture cleanup

## Goal

Apply OCP/MECE/DRY/perf improvements discovered during the upgrade. Mechanical
and structural cleanups that don't change behavior.

## Files

- `src/etree.rs` — `cmd_parsers` perf fix, command enum, transform split
- `src/crypto.rs` — `&Box<dyn CryptoPolicy>` → `&dyn CryptoPolicy`
- `src/cipher.rs`, `src/pbkdf.rs`, `src/cas.rs`, `src/prot.rs` — same
- `src/lib.rs` — eliminate the `csep_arg!` macro (now redundant thanks to
  clap 4 `value_delimiter`), inline small helpers

## Changes

### 9.1 `cmd_parsers` HashMap rebuilt per command line — perf + design

In `etree::parse`, the dispatch table is reconstructed inside the per-line
loop:

```rust
let mut cmd_parsers: HashMap<&str, Parser> = HashMap::new();
cmd_parsers.insert("DATA", parse_data);
cmd_parsers.insert("BEGIN", parse_begin);
...
```

This allocates a HashMap for every line that begins with the left separator.
On a 10k-line file with 100 commands, that's 100 throwaway HashMaps.

Replace with a `match` on a small enum:

```rust
#[derive(Copy, Clone, Debug)]
enum Command { Begin, End, Data, Stored, Encrypted }

impl Command {
    fn from_keyword(kw: &str) -> Option<Self> {
        match kw {
            "BEGIN"     => Some(Self::Begin),
            "END"       => Some(Self::End),
            "DATA"      => Some(Self::Data),
            "STORED"    => Some(Self::Stored),
            "ENCRYPTED" => Some(Self::Encrypted),
            _           => None,
        }
    }
}
```

Adding a new command = new enum variant + one match arm in the dispatcher +
the parser fn. OCP-respecting (compiler enforces exhaustiveness once we
match on the enum everywhere), zero allocations.

### 9.2 `&Box<dyn CryptoPolicy>` → `&dyn CryptoPolicy`

Throughout `src/crypto.rs`, `src/cipher.rs`, `src/pbkdf.rs`, `src/cas.rs`,
`src/prot.rs`, functions take `&Box<dyn CryptoPolicy>`. This is a clippy lint
(`borrowed_box`); the Box is unnecessary when we only need the trait object.
Replace with `&dyn CryptoPolicy`. Call sites pass `&*paops.policy` or just
`&paops.policy` (the latter auto-derefs through `Box`).

### 9.3 Split `etree::transform` into per-node handlers

`transform` is currently a ~200-line match with deeply nested logic per arm.
Split into:

```rust
fn transform(text_in: &TextTree, paops: &mut ParseOps) -> Result<TextTree> {
    let mut out = Vec::with_capacity(text_in.len());
    for node in text_in {
        let new_node = match node {
            TextNode::Plain(_)         => node.clone(),
            TextNode::Data(_)          => node.clone(),
            TextNode::BeginEnd { .. }  => transform_begin_end(node, paops)?,
            TextNode::Encrypted { .. } => transform_encrypted(node, paops)?,
            TextNode::Stored { .. }    => transform_stored(node, paops)?,
        };
        out.push(new_node);
    }
    Ok(out)
}
```

Each handler owns one node kind (MECE). The `Plain`/`Data` arms become
trivial pass-throughs.

### 9.4 Remove dead/redundant allocations

- `format!("{}$iv={}", &cipheropts.alg, ...).to_string()` — `format!` already
  returns `String`; drop the `.to_string()` (in `src/prot.rs::encrypt`).
- `to_botan_pbkdf` returns `String` for a value used once; change to `Cow<
  'static, str>` or just return the static strings directly.
- `let mut trimmed = line.trim().replacen(...)` clones the entire line; we
  can borrow.

### 9.5 Eliminate `csep_arg!` macro

After clap 4 migration (phase 07), comma-separated values arrive pre-split
into `Vec<String>`. The macro that did post-hoc splitting is dead. Delete it.

### 9.6 `paops.level` recursion counter

Currently mutated across recursive `transform` calls. Keep as-is — it's the
right shape for the algorithm — but add a debug-assert that it returns to its
starting value after each top-level call.

### 9.7 Test coverage

For each behavioral guarantee in `transform` and `parse`, ensure there's a
spec. Current coverage is good for the happy path via `tests/cli/*`; add
unit tests inside `etree.rs` for the edge cases the CLI tests don't reach:
malformed `BEGIN` without `END`, nested BEGIN mismatches, empty ENCRYPTED
body, `DATA` outside an ENCRYPTED, etc. (Some of these already exist —
audit, fill gaps.)

## What NOT to refactor

Don't:
- Replace `TextNode` enum with a trait-object hierarchy. The enum is correct
  here — node kinds are closed and small.
- Extract a `Policy` registry. Two policies don't justify a plugin system.
- Move `pbkdf_legacy` into a separate file. It's six lines.
- Introduce `Anyhow` for `main()`. We translate to `exit(1)` deliberately.

## Verification

```
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Rollback

The refactor is incremental and behavior-preserving. Each sub-change is
git-revertable independently.
