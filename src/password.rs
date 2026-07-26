// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Password reading. Extracted from `prot.rs` so the high-level
//! `encrypt`/`decrypt` functions don't carry TTY/rpassword concerns.
//!
//! `get_password` is TTY-aware: interactive sessions go through
//! rpassword's TTY-backed prompt (echo suppression, reads from
//! `/dev/tty`); piped sessions go through `prompt_password_with_config`
//! with stdin/stdout, and the repeat-verification prompt is skipped
//! when stdin isn't a TTY (a script already trusts its input).

use crate::error::{Error, Result};
use std::io::IsTerminal;

/// Prompt the user for a password.
///
/// When `rep` is true and stdin is a TTY, the prompt is repeated and
/// the two values must match (with retry on mismatch). When stdin is
/// not a TTY, repetition is skipped — piped input is trusted by the
/// caller.
pub fn get_password(name: &str, rep: bool) -> Result<String> {
    let prompt = format!("Password for {}: ", name);
    let pass = read_password(&prompt)?;
    if rep && std::io::stdin().is_terminal() {
        let again_prompt = format!("Repeat password for {}: ", name);
        let again = read_password(&again_prompt)?;
        if pass != again {
            eprintln!("Password mismatch. Try again.");
            return get_password(name, rep);
        }
    }
    Ok(pass)
}

/// If stdin is a TTY, use rpassword's TTY-backed prompt (echo
/// suppression, reads from `/dev/tty`). Otherwise read from stdin so
/// callers can pipe passwords in scripts and tests.
fn read_password(prompt: &str) -> Result<String> {
    use rpassword::ConfigBuilder;
    use std::io::{stdin, stdout};
    let pass = if stdin().is_terminal() {
        rpassword::prompt_password(prompt)
            .map_err(|e| Error::msg(format!("password prompt failed: {e}")))?
    } else {
        let config = ConfigBuilder::new()
            .input_reader(stdin())
            .output_writer(stdout())
            .build();
        rpassword::prompt_password_with_config(prompt, config)
            .map_err(|e| Error::msg(format!("password read failed: {e}")))?
    };
    // Strip a trailing CR so CRLF-terminated piped input (e.g. from
    // Windows or some terminals) is treated identically to
    // LF-terminated input.
    Ok(pass.trim_end_matches('\r').to_string())
}
