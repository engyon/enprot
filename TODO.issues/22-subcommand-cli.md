# 22 — Command-style CLI

## Problem

Today every operation is a flag (`-e`, `-d`, `-s`, `-f`, `-E`) on a single
flat argument list. Multi-operation invocations read right-to-left and are
hard to scan:

```
enprot -e a -e b -d c -k a=1 -k b=2 -k c=3 file.ept
```

## Approach

Subcommands. Each operation becomes its own subcommand; shared options
(verbose, policy, casdir, etc.) live in a `CommonArgs` struct that's
`#[command(flatten)]`-ed into each subcommand.

```rust
#[derive(Parser)]
#[command(name = "enprot", version, about = "…")]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt WORD segments.
    Encrypt { words: Words, #[command(flatten)] opts: EncryptOpts, files: Vec<PathBuf> },
    /// Decrypt WORD segments.
    Decrypt { words: Words, #[command(flatten)] opts: CommonOperationArgs, files: Vec<PathBuf> },
    /// Store (unencrypted) WORD segments to CAS.
    Store  { words: Words, #[command(flatten)] opts: CommonOperationArgs, files: Vec<PathBuf> },
    /// Fetch (unencrypted) WORD segments from CAS.
    Fetch  { words: Words, #[command(flatten)] opts: CommonOperationArgs, files: Vec<PathBuf> },
    /// Encrypt and store WORD segments.
    EncryptStore { words: Words, #[command(flatten)] opts: EncryptOpts, files: Vec<PathBuf> },
}
```

### Design decisions

- **Hard cut, no flag-mode alias.** Keeping both shapes doubles the test
  matrix and confuses users. The flat-flag form is gone.
- **WORD list is positional**, not a flag. `enprot encrypt Agent_007 GEHEIM
  file.ept` is the natural spelling. Multi-value is via repetition or
  space separation.
- **`-k`/`--key` is shared.** Stays in `CommonArgs` since every operation
  can need a password.
- **Crypto knobs (pbkdf, cipher, salt, IV, etc.) move under `EncryptOpts`**
  since they're meaningless for decrypt/store/fetch. This is the OCP win:
  the surface for "things only encrypt cares about" is now scoped to one
  struct.
- **`--max-depth`, `--left-separator`, `--right-separator`** move to
  `CommonArgs` (they're parsing concerns).

### Migration

Existing test invocations:

```
enprot -e Agent_007 --pbkdf legacy -k Agent_007=password file.ept
```

become:

```
enprot encrypt Agent_007 --pbkdf legacy -k Agent_007=password file.ept
```

The README tutorial and every test in `tests/cli/*.rs` need updating.
That's a lot of mechanical edits but each is a 1-line transform.

### Backward compatibility

None. This is a hard cut. Users scripting enprot need to update. The
commit message will spell this out and the version should bump to 0.4.0
when released.

## Files

- `src/lib.rs` — full Cli rewrite.
- `src/consts.rs` — possibly add a `Words` newtype if useful.
- `tests/cli/*.rs` — update every invocation.
- `tests/tests.rs` — `app_main` callers in `pbkdf.rs` test need to switch
  to subcommand form.
- `README.adoc` — tutorial section rewrite.
- `CLAUDE.md` — CLI wiring section update.

## Verification

```
cargo test
cargo run -- encrypt Agent_007 --pbkdf legacy -k Agent_007=password sample/test.ept
cargo run -- --help
cargo run -- encrypt --help
```

`cargo run -- --help` lists the subcommands. `cargo run -- encrypt --help`
shows the encrypt-specific options.

## Rollback

Revert `src/lib.rs` and the test/README updates. Large but mechanical.

## Out of scope

- Shell completion generation (`clap_complete`) — could add as a follow-up.
- Interactive mode (REPL-ish) — not requested.
