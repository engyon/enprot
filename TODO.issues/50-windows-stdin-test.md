# 50 — `encrypt_decrypt_agent007_stdin_pass` test fails on Windows

## Status: resolved by PR #57

The test was Windows-broken because the old `rpassword 2` API
(`prompt_password_stdout`) didn't behave correctly when stdin was piped
on Windows. PR #57 replaced it with a TTY-aware reader:

```rust
fn read_password(prompt: &str) -> std::io::Result<String> {
    use rpassword::ConfigBuilder;
    use std::io::{IsTerminal, stdin, stdout};
    let pass = if stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        let config = ConfigBuilder::new()
            .input_reader(stdin())
            .output_writer(stdout())
            .build();
        rpassword::prompt_password_with_config(prompt, config)?
    };
    Ok(pass.trim_end_matches('\r').to_string())
}
```

`rpassword 7` is cross-platform (uses `console` crate on Windows,
`/dev/tty` on Unix). The `\r` trim handles CRLF-terminated piped input.

The remaining artifact: the test still carries `#[cfg(unix)]` because at
the time it was added, Windows was broken. Now it isn't.

## Action

Remove the `#[cfg(unix)]` gate from `tests/cli/encrypt_decrypt.rs::encrypt_decrypt_agent007_stdin_pass`. Leave a comment on the issue
pointing at this file and at commit `998206a` (PR #57 merge).

## Verification

CI's `windows-latest` job runs the test and it passes.

## Rollback

Re-add `#[cfg(unix)]` if Windows CI reveals an unrelated rpassword bug.
