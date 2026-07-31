# 01 — FFI: actually run the pipeline

**Priority**: P0
**Status**: specified

## Problem

`enprot_process()` in `enprot-ffi/src/lib.rs` is a JSON-validation stub. It parses the config, checks that `operation` and `file` are present, then returns `ENPROT_OK` without doing anything. The Python, Node, Go, and Ruby bindings all expose this stub — they pass their test suites but cannot actually encrypt, decrypt, store, or fetch.

This is the single biggest gap between the bindings' promise and what they deliver. Every binding README currently has a disclaimer like "FFI is a stub; will be extended".

## Goals

- `pyenprot.encrypt("file.toml", words={"SECRET": "pw"})` actually encrypts `file.toml` in place.
- Same for Node, Go, Ruby.
- All four language bindings round-trip end-to-end in their CI matrix (today the tests only validate that the helper builds the right JSON shape — they don't run the pipeline).

## Non-goals

- A typed Config struct in the FFI surface. The wire format stays JSON. (See [16-ff-enprot-pipeline-ffi] for a future typed-config refactor.)
- Streaming output, progress callbacks, or async — the FFI is synchronous for now.

## Design

### Approach: JSON config → argv → `app_main`

`enprot::app_main(args)` already exists in `src/cli.rs` and dispatches every subcommand. It takes any iterator of `OsString`-like values and returns `Result<()>`. Reusing it from the FFI means every CLI feature (PBKDF options, recipient keys, policy, anchor signing, etc.) is available to bindings for free, with no second implementation to maintain.

```rust
// enprot-ffi/src/lib.rs

fn json_to_argv(config: &serde_json::Value) -> Result<Vec<String>, String> {
    let op = config["operation"].as_str()
        .ok_or("missing 'operation'")?;
    let file = config["file"].as_str()
        .ok_or("missing 'file'")?;

    let mut argv = vec!["enprot".to_string(), op.to_string()];

    if let Some(words) = config["words"].as_object() {
        for (k, v) in words {
            let pw = v.as_str().ok_or_else(|| format!("words.{k}: expected string"))?;
            argv.push("-w".into());
            argv.push(format!("{k}={pw}"));
        }
    }
    if let Some(c) = config["cipher"].as_str() { argv.push("--cipher".into()); argv.push(c.into()); }
    if let Some(p) = config["policy"].as_str() { argv.push("--policy".into()); argv.push(p.into()); }
    if let Some(c) = config["casdir"].as_str() { argv.push("-c".into()); argv.push(c.into()); }
    if let Some(s) = config["separators"].as_str() { argv.push("--separators".into()); argv.push(s.into()); }
    // recipient, recipient-priv, anchor, etc. follow the same pattern.

    argv.push(file.into());
    Ok(argv)
}

pub unsafe extern "C" fn enprot_process(config_json: *const c_char) -> EnprotResult {
    // null + UTF-8 + JSON-shape validation as today.

    let argv = match json_to_argv(&config) {
        Ok(a) => a,
        Err(msg) => return EnprotResult::err(ENPROT_ERR_INVALID, &msg),
    };

    #[cfg(feature = "cli")]
    {
        match enprot::app_main(argv) {
            Ok(()) => EnprotResult::ok(),
            Err(e) => classify_error(e),
        }
    }
    #[cfg(not(feature = "cli"))]
    {
        let _ = argv;
        EnprotResult::err(ENPROT_ERR_INVALID, "FFI was built without 'cli' feature; rebuild with --features cli")
    }
}
```

### Error classification

Today every error from `app_main` becomes `ENPROT_ERR_INVALID`. Map by type:

| Rust error kind | FFI code |
|---|---|
| `Error::Io { .. }` | `ENPROT_ERR_IO` |
| `Error::Botan { .. }` | `ENPROT_ERR_CRYPTO` |
| `Error::Parse { .. }` | `ENPROT_ERR_PARSE` |
| Other (`Error::Msg`) | `ENPROT_ERR_INVALID` |

This requires [02-typed-errors](02-typed-errors.md) to land first. Interim: classify by string-prefix matching (`"failed to open"` → IO, etc.), to be replaced once typed errors exist.

### CI coverage

The `bindings.yml` workflow's `python` / `nodejs` / `tools` jobs currently run pytest / node:test / etc. against the stubbed FFI. Add an end-to-end test per language that:

1. Creates a temp file with a `BEGIN SECRET … END SECRET` block.
2. Calls `encrypt(file, words={"SECRET": "hunter2"})`.
3. Reads the file back; asserts a `// <( ENCRYPTED SECRET )>` block now exists with `DATA …` lines.
4. Calls `decrypt` with the same password; asserts the original plaintext returns.

These tests fail today (because the FFI is a no-op) and will start passing when this TODO ships.

### Forward-compatibility

The `app_main`-via-argv approach has known limits: it can't carry binary secrets safely (they'd land in process args), and it forces a round-trip through clap parsing on every call. The [16-ff-enprot-pipeline-ffi] TODO introduces a typed `EnprotConfig` struct that bypasses clap. Once that lands, the FFI switches to it; the JSON wire format and language bindings stay the same.

## Implementation plan

1. Add `enprot` as a path dependency of `enprot-ffi` (already done — verify).
2. Implement `json_to_argv` + classify_error.
3. Replace the stub body of `enprot_process`.
4. Add an integration test in `enprot-ffi/tests/end_to_end.rs` that exercises encrypt/decrypt/store/fetch round-trips.
5. Update the Python / Node / Go / Ruby test suites to include the round-trip tests (gated on `ENPROT_LIB` being set).

## Test plan

- [ ] `enprot-ffi` end-to-end integration tests pass on linux + macOS.
- [ ] Python `test_encrypt_round_trip` passes in CI.
- [ ] Node `test/round-trip.js` passes in CI.
- [ ] Go `Test_RoundTrip` passes in CI.
- [ ] Ruby `test_round_trip.rb` passes in CI.
- [ ] FFI still returns `ENPROT_ERR_INVALID` for malformed JSON.

## Out of scope

- Async FFI (would require a callback-style API).
- Per-call PBKDF cache warming.
- Streaming large files (see [05-streaming-io]).
