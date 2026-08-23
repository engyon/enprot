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

//! EPT markup parser. Line-oriented: a non-directive line folds into
//! the preceding `Plain` node; a directive line is dispatched to the
//! per-command parser by `Command::from_keyword`.

use std::collections::{BTreeMap, HashSet};
use std::io::BufRead;

use crate::error::{Error, Result};
use crate::etree::{Command, ParseOps, TextNode, TextTree, parse_error};
use crate::utils;

/// In-progress frame on the parser stack. The `text` accumulator is
/// always the "current target" — what new nodes get pushed onto. When
/// a frame opens, the outer text is saved into the frame and `text`
/// is cleared; when the frame closes, the saved outer text becomes
/// the new accumulator and the just-collected `text` becomes the
/// frame's children.
///
/// `Conflict` is the one variant that collects into *two* children
/// (`ours`, `theirs`); `mode` tracks which side `text` is currently
/// filling. OURS/THEIRS directives flip the mode and stash the
/// accumulated nodes into the appropriate field.
enum Frame {
    BeginEnd {
        keyw: String,
        outer: TextTree,
    },
    Encrypted {
        keyw: String,
        outer: TextTree,
        extfields: BTreeMap<String, String>,
    },
    Conflict {
        keyw: String,
        outer: TextTree,
        ours: TextTree,
        mode: ConflictMode,
    },
    /// IMMUTABLE/MUTABLE frame. The hash field carries the declared
    /// content hash from the IMMUTABLE directive; verified on close.
    Immutable {
        name: String,
        hashalg: String,
        hash: String,
        outer: TextTree,
    },
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum ConflictMode {
    Ours,
    Theirs,
}

#[tracing::instrument(skip(buf_in, paops), fields(file = %paops.runtime.fname))]
pub fn parse<R>(buf_in: R, paops: &mut ParseOps) -> Result<TextTree>
where
    R: BufRead,
{
    if paops.max_depth != 0 && paops.runtime.level > paops.max_depth {
        return Err(Error::Parse {
            file: paops.runtime.fname.clone(),
            lineno: 0,
            msg: format!("maximum recursion depth ({}) exceeded", paops.max_depth),
        });
    }

    let mut text = Vec::new();
    let mut lineno = 0;
    let mut pstack: Vec<Frame> = Vec::new();

    for line_in in buf_in.lines() {
        let line = line_in?;
        lineno += 1;

        if !line.trim_start().starts_with(&paops.separators.left) {
            if let Some(TextNode::Plain(last)) = text.last_mut() {
                last.push('\n');
                last.push_str(&line);
                continue;
            }
            text.push(TextNode::Plain(line.clone()));
            continue;
        }

        // Directive parsing: avoid allocating a new String via
        // replacen. Work with slices from the original line.
        // (TODO.finalize/40 — parser perf.)
        let trimmed = line.trim();
        let after_left = trimmed
            .strip_prefix(&paops.separators.left)
            .unwrap_or(trimmed);
        let inner = match after_left.strip_suffix(&paops.separators.right) {
            Some(s) => s,
            None => {
                return Err(parse_error(
                    paops,
                    lineno,
                    &line,
                    format!("Right separator '{}' missing.", paops.separators.right),
                ));
            }
        };
        let mut parts = inner.split_whitespace();
        let kw = match parts.next() {
            Some(k) => k,
            None => continue,
        };

        let parsed = match Command::from_keyword(kw) {
            Some(c) => c,
            None => {
                return Err(parse_error(
                    paops,
                    lineno,
                    &line,
                    format!("Unknown section '{}'.", kw),
                ));
            }
        };

        let rest: Vec<&str> = parts.collect();
        match parsed {
            Command::Data => parse_data(&rest, &line, lineno, paops, &mut text)?,
            Command::Begin => parse_begin(&rest, &line, lineno, paops, &mut pstack, &mut text)?,
            Command::Encrypted => {
                parse_encrypted(&rest, &line, lineno, paops, &mut pstack, &mut text)?
            }
            Command::End => parse_end(&rest, &line, lineno, paops, &mut pstack, &mut text)?,
            Command::Stored => parse_stored(&rest, &line, lineno, paops, &mut text)?,
            Command::Chain => parse_chain(&rest, &line, lineno, paops, &mut text)?,
            Command::Include => parse_include(&rest, &line, lineno, paops, &mut text)?,
            Command::Conflict => {
                parse_conflict(&rest, &line, lineno, paops, &mut pstack, &mut text)?
            }
            Command::Ours => parse_ours(&line, lineno, paops, &mut pstack, &mut text)?,
            Command::Theirs => parse_theirs(&line, lineno, paops, &mut pstack, &mut text)?,
            Command::Immutable => {
                parse_immutable(&rest, &line, lineno, paops, &mut pstack, &mut text)?
            }
            Command::Mutable => parse_mutable(&rest, &line, lineno, paops, &mut pstack, &mut text)?,
            Command::Muted => parse_muted(&rest, &line, lineno, paops, &mut text)?,
            Command::Key => parse_key(&rest, &line, lineno, paops, &mut text)?,
            Command::Unkey => parse_unkey(&rest, &line, lineno, paops, &mut text)?,
            Command::Cert => parse_cert(&rest, &line, lineno, paops, &mut text)?,
            Command::Uncert => parse_uncert(&rest, &line, lineno, paops, &mut text)?,
        }
    }

    if !pstack.is_empty() {
        for top in pstack.into_iter().rev() {
            match top {
                Frame::BeginEnd { keyw, .. } => {
                    eprintln!("Parse: BEGIN {} without END.", keyw);
                }
                Frame::Encrypted { keyw, .. } => {
                    eprintln!("Parse: ENCRYPTED {} without END.", keyw);
                }
                Frame::Conflict { keyw, .. } => {
                    eprintln!("Parse: CONFLICT {} without END.", keyw);
                }
                Frame::Immutable { name, .. } => {
                    eprintln!("Parse: IMMUTABLE {} without MUTABLE.", name);
                }
            }
        }
        return Err(Error::Parse {
            file: paops.runtime.fname.clone(),
            lineno: 0,
            msg: "Unclosed section".into(),
        });
    }

    Ok(text)
}

fn parse_data(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    for tok in cmd {
        let mut data = match utils::base64_decode(tok) {
            Ok(d) => d,
            Err(e) => {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("Error decoding base64 in '{}': {}", tok, e),
                ));
            }
        };
        if let Some(TextNode::Data(last)) = text.last_mut() {
            last.append(&mut data);
        } else {
            text.push(TextNode::Data(data));
        }
    }
    Ok(())
}

fn parse_begin(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "BEGIN needs a single keyword.",
        ));
    }
    paops.runtime.level += 1;
    pstack.push(Frame::BeginEnd {
        keyw: cmd[0].to_owned(),
        outer: std::mem::take(text),
    });
    Ok(())
}

pub(crate) fn parse_encrypted_extfields(
    cmd: &[&str],
    paops: &ParseOps,
    lineno: i32,
    line: &str,
) -> Result<BTreeMap<String, String>> {
    let mut extfields: BTreeMap<String, String> = BTreeMap::new();
    for field in cmd.iter().rev() {
        if field.find(':').is_none() {
            break;
        }
        let (key, value) = field.split_once(':').unwrap();

        if extfields.contains_key(key) {
            return Err(parse_error(
                paops,
                lineno,
                line,
                format!("Duplicate extended field '{}'", key),
            ));
        }
        extfields.insert(key.to_string(), value.to_string());
    }
    Ok(extfields)
}

fn parse_encrypted(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    let extfields = parse_encrypted_extfields(cmd, paops, lineno, line)?;
    let param_count = cmd.len() - extfields.len();
    let extfield_keys: HashSet<String> = extfields.keys().cloned().collect();
    let known_extfields: HashSet<String> = ["pbkdf".to_string(), "cipher".to_string()]
        .into_iter()
        .collect();
    if extfield_keys.difference(&known_extfields).next().is_some() {
        eprintln!("Warning: Unrecognized extended field(s) present");
    }

    match param_count {
        1 => {
            paops.runtime.level += 1;
            pstack.push(Frame::Encrypted {
                keyw: cmd[0].to_owned(),
                outer: std::mem::take(text),
                extfields,
            });
            Ok(())
        }
        2 => {
            if cmd[1].len() != 64 {
                return Err(parse_error(paops, lineno, line, "Invalid CAS identifier"));
            }
            let node = vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: cmd[1].to_string(),
            }];
            text.push(TextNode::Encrypted {
                keyw: cmd[0].to_string(),
                txt: node,
                extfields,
            });
            Ok(())
        }
        _ => Err(parse_error(
            paops,
            lineno,
            line,
            format!(
                "ENCRYPTED has wrong number of parameters ({}).",
                param_count
            ),
        )),
    }
}

fn parse_end(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() > 1 {
        return Err(parse_error(paops, lineno, line, "Unknown padding in END."));
    }

    match pstack.pop() {
        Some(Frame::BeginEnd { keyw, outer }) => {
            if !cmd.is_empty() && keyw != cmd[0] {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("END mismatch (expected '{}').", keyw),
                ));
            }
            let node = TextNode::BeginEnd {
                keyw,
                txt: std::mem::take(text),
            };
            *text = outer;
            text.push(node);
            paops.runtime.level -= 1;
            Ok(())
        }
        Some(Frame::Encrypted {
            keyw,
            outer,
            extfields,
        }) => {
            if cmd.is_empty() || keyw != cmd[0] {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("END mismatch (expected '{}').", keyw),
                ));
            }
            if text.len() != 1 {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!(
                        "{} elements in encrypted {} (must be a single DATA or STORED).",
                        text.len(),
                        keyw
                    ),
                ));
            }
            match text[0] {
                TextNode::Data(_) | TextNode::Stored { .. } => {
                    let node = TextNode::Encrypted {
                        keyw,
                        txt: std::mem::take(text),
                        extfields,
                    };
                    *text = outer;
                    text.push(node);
                    paops.runtime.level -= 1;
                    Ok(())
                }
                _ => Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("Not DATA or STORED element in encrypted {}.", keyw),
                )),
            }
        }
        Some(Frame::Conflict {
            keyw,
            outer,
            ours,
            mode,
        }) => {
            if !cmd.is_empty() && keyw != cmd[0] {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("END mismatch (expected '{}').", keyw),
                ));
            }
            // Whatever was in `text` belongs to the side currently
            // in `mode`. The other side was already stashed when the
            // mode-switch directive fired.
            let (ours, theirs) = match mode {
                ConflictMode::Ours => (std::mem::take(text), ours),
                ConflictMode::Theirs => (ours, std::mem::take(text)),
            };
            let node = TextNode::Conflict { keyw, ours, theirs };
            *text = outer;
            text.push(node);
            paops.runtime.level -= 1;
            Ok(())
        }
        Some(Frame::Immutable { name, .. }) => Err(parse_error(
            paops,
            lineno,
            line,
            format!(
                "END inside IMMUTABLE {} — use MUTABLE {} to close.",
                name, name
            ),
        )),
        None => Err(parse_error(
            paops,
            lineno,
            line,
            "END without a start clause.",
        )),
    }
}

fn parse_stored(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 2 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "STORED needs two parameters.",
        ));
    }
    text.push(TextNode::Stored {
        keyw: cmd[0].to_owned(),
        cas: cmd[1].to_owned(),
    });
    Ok(())
}

/// Parse a `CHAIN` directive line. All fields use the same
/// `key:value` extfield format as `ENCRYPTED`; the resulting map
/// becomes a [`TextNode::Chain`]. Required fields (`parents`,
/// `signer`, `payload`, `sig`) are validated by the verifier
/// (`verify-chain`, TODO.finalize/18), not here — the parser
/// accepts anything that parses as extfields so unknown-future
/// fields don't break old parsers.
fn parse_chain(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    let extfields = parse_encrypted_extfields(cmd, paops, lineno, line)?;
    if extfields.is_empty() {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "CHAIN needs at least one key:value field (parents / signer / payload / sig).",
        ));
    }
    text.push(TextNode::Chain { extfields });
    Ok(())
}

/// Parse an `INCLUDE <hash>` directive. The hash is a CAS blob ID
/// pointing to another EPT file. Resolution (loading the referenced
/// file, recursive verification) is NOT done by the parser — callers
/// like `verify-chain --include-path` handle it.
fn parse_include(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "INCLUDE needs exactly one hash parameter.",
        ));
    }
    text.push(TextNode::Include {
        hash: cmd[0].to_owned(),
    });
    Ok(())
}

/// Open a CONFLICT block. Like BEGIN, but the block holds two
/// labelled sub-trees (`ours`, `theirs`) instead of one. Mode starts
/// in `Ours`; the OURS directive flips the mode and stashes whatever
/// has been collected so far.
fn parse_conflict(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "CONFLICT needs a single keyword.",
        ));
    }
    paops.runtime.level += 1;
    pstack.push(Frame::Conflict {
        keyw: cmd[0].to_owned(),
        outer: std::mem::take(text),
        ours: Vec::new(),
        mode: ConflictMode::Ours,
    });
    Ok(())
}

/// `OURS` mode-switch inside a CONFLICT block. Anything collected
/// before OURS (rare — usually CONFLICT is immediately followed by
/// OURS) becomes part of the ours side, then the mode flips and
/// collection continues into `ours`. After THEIRS, OURS is an error.
fn parse_ours(
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut [Frame],
    text: &mut Vec<TextNode>,
) -> Result<()> {
    let Some(last) = pstack.last_mut() else {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "OURS outside of CONFLICT block.",
        ));
    };
    let Frame::Conflict { ours, mode, .. } = last else {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "OURS inside non-CONFLICT block.",
        ));
    };
    if *mode == ConflictMode::Theirs {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "OURS after THEIRS in CONFLICT block.",
        ));
    }
    // Re-attach the accumulated nodes to the ours side, then keep
    // collecting into ours via `text`. (When THEIRS arrives later it
    // will stash `text` into ours in turn.)
    ours.append(text);
    *mode = ConflictMode::Ours;
    Ok(())
}

/// `THEIRS` mode-switch inside a CONFLICT block. Stashes the
/// accumulated text into `ours` and starts collecting into `theirs`.
fn parse_theirs(
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut [Frame],
    text: &mut Vec<TextNode>,
) -> Result<()> {
    let Some(last) = pstack.last_mut() else {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "THEIRS outside of CONFLICT block.",
        ));
    };
    let Frame::Conflict { ours, mode, .. } = last else {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "THEIRS inside non-CONFLICT block.",
        ));
    };
    if *mode == ConflictMode::Theirs {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "THEIRS after THEIRS in CONFLICT block.",
        ));
    }
    ours.append(text);
    *mode = ConflictMode::Theirs;
    Ok(())
}

// ---------------------------------------------------------------------
// IMMUTABLE / MUTABLE / MUTED (RSD spec §"Immutable Blocks")
// ---------------------------------------------------------------------

/// Parse `IMMUTABLE <name> <hashalg>=<hash>` — opens a content-
/// addressed integrity block. Pairs with MUTABLE as the closer.
fn parse_immutable(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 2 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "IMMUTABLE needs <name> <hashalg>=<hash>.",
        ));
    }
    let name = cmd[0].to_owned();
    let (hashalg, hash) = parse_hash_spec(cmd[1], paops, lineno, line, "IMMUTABLE")?;
    paops.runtime.level += 1;
    pstack.push(Frame::Immutable {
        name,
        hashalg,
        hash,
        outer: std::mem::take(text),
    });
    Ok(())
}

/// Parse `MUTABLE <name>` — closes an IMMUTABLE block. The content
/// accumulated in `text` becomes the block's body; the declared
/// hash is recorded (verification happens at `verify` time, not
/// parse time, to keep the parser policy-agnostic).
fn parse_mutable(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<Frame>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "MUTABLE needs a single name.",
        ));
    }
    match pstack.pop() {
        Some(Frame::Immutable {
            name,
            hashalg,
            hash,
            outer,
        }) => {
            if name != cmd[0] {
                return Err(parse_error(
                    paops,
                    lineno,
                    line,
                    format!("MUTABLE mismatch (expected '{}').", name),
                ));
            }
            let node = TextNode::Immutable {
                name,
                hashalg,
                hash,
                txt: std::mem::take(text),
            };
            *text = outer;
            text.push(node);
            paops.runtime.level -= 1;
            Ok(())
        }
        Some(_) => Err(parse_error(
            paops,
            lineno,
            line,
            "MUTABLE inside non-IMMUTABLE block.",
        )),
        None => Err(parse_error(
            paops,
            lineno,
            line,
            "MUTABLE without IMMUTABLE.",
        )),
    }
}

/// Parse `MUTED <name> <hashalg>=<hash>` — standalone directive for
/// a sanitized IMMUTABLE block whose content lives in CAS.
fn parse_muted(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 2 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "MUTED needs <name> <hashalg>=<hash>.",
        ));
    }
    let name = cmd[0].to_owned();
    let (hashalg, hash) = parse_hash_spec(cmd[1], paops, lineno, line, "MUTED")?;
    text.push(TextNode::Muted {
        name,
        hashalg,
        hash,
    });
    Ok(())
}

/// Parse a `<hashalg>=<hash>` spec like `sha384=ABCDEF…` or
/// `sha3-256=…`. Returns (algorithm_name, hex_hash).
fn parse_hash_spec(
    s: &str,
    paops: &ParseOps,
    lineno: i32,
    line: &str,
    directive: &str,
) -> Result<(String, String)> {
    let (alg, hash) = s.split_once('=').ok_or_else(|| {
        parse_error(
            paops,
            lineno,
            line,
            format!("{} needs <hashalg>=<hash>, got '{}'", directive, s),
        )
    })?;
    if hash.is_empty() {
        return Err(parse_error(
            paops,
            lineno,
            line,
            format!("{} hash is empty", directive),
        ));
    }
    Ok((alg.to_string(), hash.to_string()))
}

// ---------------------------------------------------------------------
// KEY / UNKEY / CERT / UNCERT (RSD spec §"Group keys")
// ---------------------------------------------------------------------

/// Parse `KEY <name> <hashalg>=<hash>` — declares a key binding.
fn parse_key(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 2 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "KEY needs <name> <hashalg>=<hash>.",
        ));
    }
    let name = cmd[0].to_owned();
    let (hashalg, hash) = parse_hash_spec(cmd[1], paops, lineno, line, "KEY")?;
    text.push(TextNode::Key {
        name,
        hashalg,
        hash,
    });
    Ok(())
}

/// Parse `UNKEY <name>` — ends a KEY binding scope.
fn parse_unkey(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "UNKEY needs a single name.",
        ));
    }
    text.push(TextNode::Unkey {
        name: cmd[0].to_owned(),
    });
    Ok(())
}

/// Parse `CERT <name> <hashalg>=<hash>` — declares a public-key cert.
fn parse_cert(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 2 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "CERT needs <name> <hashalg>=<hash>.",
        ));
    }
    let name = cmd[0].to_owned();
    let (hashalg, hash) = parse_hash_spec(cmd[1], paops, lineno, line, "CERT")?;
    text.push(TextNode::Cert {
        name,
        hashalg,
        hash,
    });
    Ok(())
}

/// Parse `UNCERT <name>` — ends a CERT binding scope.
fn parse_uncert(
    cmd: &[&str],
    line: &str,
    lineno: i32,
    paops: &ParseOps,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() != 1 {
        return Err(parse_error(
            paops,
            lineno,
            line,
            "UNCERT needs a single name.",
        ));
    }
    text.push(TextNode::Uncert {
        name: cmd[0].to_owned(),
    });
    Ok(())
}

/// Wire-format spec for `parse` (TODO.complete/49).
///
/// Two parts:
///
/// 1. **Malformed-input table** — every error branch the parser can
///    take, driven from a (input, expected-message) row. Table-driven
///    so a new branch is one row, not one test function (OCP).
/// 2. **Shape tests** — the positive forms the error table can't
///    reach: Conflict round-trip, keyword-less END, the ENCRYPTED
///    2-parameter CAS form, DATA concatenation, and Plain folding.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn paops() -> ParseOps {
        let mut p = ParseOps::new(crate::crypto::default_policy()).unwrap();
        p.runtime.fname = "<spec>".into();
        p
    }

    fn parse_input(input: &str) -> std::result::Result<TextTree, crate::error::Error> {
        let mut p = paops();
        parse(BufReader::new(input.as_bytes()), &mut p)
    }

    fn assert_err(input: &str, expect: &str) {
        let err = parse_input(input)
            .err()
            .unwrap_or_else(|| panic!("expected error containing {expect:?} for input {input:?}"));
        assert!(
            err.to_string().contains(expect),
            "input {input:?}\n  got:  {err}\n  want: …{expect}…"
        );
    }

    #[test]
    fn malformed_inputs_are_rejected_with_specific_messages() {
        let cases: &[(&str, &str)] = &[
            // Structural errors.
            ("// <( BEGIN W", "Right separator"), // no `)>`
            ("// <( FROBNICATE W )>", "Unknown section 'FROBNICATE'"),
            // Arity / shape errors per directive.
            ("// <( DATA !!!not-base64!!! )>", "Error decoding base64"),
            ("// <( BEGIN )>", "BEGIN needs a single keyword"),
            ("// <( BEGIN A B )>", "BEGIN needs a single keyword"),
            (
                "// <( ENCRYPTED W cipher:a cipher:a )>",
                "Duplicate extended field",
            ),
            ("// <( ENCRYPTED W short )>", "Invalid CAS identifier"),
            ("// <( ENCRYPTED )>", "wrong number of parameters"),
            ("// <( END W )>", "END without a start clause"),
            (
                "// <( ENCRYPTED W )>\n// <( END )>",
                "END mismatch (expected 'W')",
            ),
            ("// <( STORED W )>", "STORED needs two parameters"),
            ("// <( CHAIN )>", "CHAIN needs at least one key:value field"),
            ("// <( INCLUDE )>", "INCLUDE needs exactly one hash"),
            ("// <( CONFLICT A B )>", "CONFLICT needs a single keyword"),
            ("// <( OURS )>", "OURS outside of CONFLICT block"),
            ("// <( THEIRS )>", "THEIRS outside of CONFLICT block"),
            (
                "// <( BEGIN W )>\n// <( OURS )>",
                "OURS inside non-CONFLICT",
            ),
            (
                "// <( BEGIN W )>\n// <( THEIRS )>",
                "THEIRS inside non-CONFLICT",
            ),
            (
                "// <( IMMUTABLE N )>",
                "IMMUTABLE needs <name> <hashalg>=<hash>",
            ),
            ("// <( MUTABLE N )>", "MUTABLE without IMMUTABLE"),
            (
                "// <( BEGIN W )>\n// <( MUTABLE N )>",
                "MUTABLE inside non-IMMUTABLE",
            ),
            ("// <( MUTED N )>", "MUTED needs <name> <hashalg>=<hash>"),
            ("// <( KEY N )>", "KEY needs <name> <hashalg>=<hash>"),
            ("// <( UNKEY )>", "UNKEY needs a single name"),
            ("// <( CERT N )>", "CERT needs <name> <hashalg>=<hash>"),
            ("// <( UNCERT )>", "UNCERT needs a single name"),
            // Hash-spec errors shared by IMMUTABLE/MUTED/KEY/CERT.
            ("// <( KEY N noequals )>", "KEY needs <hashalg>=<hash>"),
            ("// <( KEY N sha256= )>", "KEY hash is empty"),
        ];
        for (input, expect) in cases {
            assert_err(input, expect);
        }
    }

    #[test]
    fn mismatched_closers_are_rejected() {
        assert_err(
            "// <( BEGIN A )>\n// <( END B )>",
            "END mismatch (expected 'A')",
        );
        assert_err(
            "// <( ENCRYPTED A )>\n// <( DATA QUJD )>\n// <( END B )>",
            "END mismatch (expected 'A')",
        );
        assert_err(
            "// <( CONFLICT A )>\n// <( OURS )>\n// <( END B )>",
            "END mismatch (expected 'A')",
        );
        assert_err(
            "// <( IMMUTABLE N sha256=ab )>\n// <( END N )>",
            "END inside IMMUTABLE N",
        );
        assert_err(
            "// <( IMMUTABLE N sha256=ab )>\n// <( MUTABLE M )>",
            "MUTABLE mismatch (expected 'N')",
        );
        assert_err("// <( END W extra )>\n", "Unknown padding in END");
    }

    #[test]
    fn encrypted_block_must_hold_exactly_one_payload() {
        // Two DATA directives inside one ENCRYPTED block still parse
        // (concatenated into one Data node) — the shape error is for
        // *elements*, so force two elements with a Stored + Data mix.
        assert_err(
            "// <( ENCRYPTED A )>\n// <( DATA QUJD )>\n// <( STORED ct x )>\n// <( END A )>",
            "must be a single DATA or STORED",
        );
        // A Plain line inside ENCRYPTED is not a payload element.
        assert_err(
            "// <( ENCRYPTED A )>\nnot a payload\n// <( END A )>",
            "Not DATA or STORED element",
        );
    }

    #[test]
    fn conflict_mode_switches_are_ordered() {
        // OURS after THEIRS is ambiguous → error.
        assert_err(
            "// <( CONFLICT A )>\n// <( OURS )>\n// <( THEIRS )>\n// <( OURS )>\n// <( END A )>",
            "OURS after THEIRS",
        );
        // THEIRS after THEIRS would silently drop the middle side.
        assert_err(
            "// <( CONFLICT A )>\n// <( OURS )>\n// <( THEIRS )>\n// <( THEIRS )>\n// <( END A )>",
            "THEIRS after THEIRS",
        );
    }

    #[test]
    fn unclosed_sections_report_their_kind() {
        assert_err("// <( BEGIN A )>", "Unclosed section");
        assert_err(
            "// <( ENCRYPTED A )>\n// <( DATA QUJD )>",
            "Unclosed section",
        );
        assert_err("// <( CONFLICT A )>\n// <( OURS )>", "Unclosed section");
        assert_err("// <( IMMUTABLE N sha256=ab )>", "Unclosed section");
    }

    #[test]
    fn max_depth_is_enforced_at_entry() {
        let mut p = paops();
        p.max_depth = 2;
        p.runtime.level = 3;
        let err = parse(BufReader::new(b"plain\n".as_ref()), &mut p).unwrap_err();
        assert!(
            err.to_string().contains("maximum recursion depth"),
            "got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // Positive shapes (error table can't reach these).
    // ------------------------------------------------------------------

    #[test]
    fn conflict_block_round_trips_into_ours_theirs() {
        let tree = parse_input(
            "// <( CONFLICT W )>\n// <( OURS )>\nour line\n// <( THEIRS )>\ntheir line\n// <( END W )>\n",
        )
        .unwrap();
        match &tree[0] {
            TextNode::Conflict { keyw, ours, theirs } => {
                assert_eq!(keyw, "W");
                assert_eq!(ours.len(), 1, "ours: {ours:?}");
                assert_eq!(theirs.len(), 1, "theirs: {theirs:?}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn conflict_content_before_ours_becomes_ours() {
        // Text between CONFLICT and OURS belongs to the ours side.
        let tree = parse_input(
            "// <( CONFLICT W )>\nleading\n// <( OURS )>\n// <( THEIRS )>\nt\n// <( END W )>\n",
        )
        .unwrap();
        match &tree[0] {
            TextNode::Conflict { ours, .. } => {
                assert!(
                    ours.iter()
                        .any(|n| matches!(n, TextNode::Plain(p) if p.contains("leading")))
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn end_without_keyword_closes_innermost() {
        // `END` bare (no WORD) is accepted and closes the innermost block.
        let tree = parse_input("// <( BEGIN W )>\nbody\n// <( END )>\n").unwrap();
        assert!(matches!(&tree[0], TextNode::BeginEnd { keyw, .. } if keyw == "W"));
    }

    #[test]
    fn encrypted_two_param_form_builds_stored_child() {
        let cas64 = "a".repeat(64);
        let tree = parse_input(&format!("// <( ENCRYPTED W {cas64} )>\n")).unwrap();
        match &tree[0] {
            TextNode::Encrypted { keyw, txt, .. } => {
                assert_eq!(keyw, "W");
                match &txt[0] {
                    TextNode::Stored { keyw, cas } => {
                        assert_eq!(keyw, "ct");
                        assert_eq!(cas, &cas64);
                    }
                    other => panic!("expected Stored child, got {other:?}"),
                }
            }
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }

    #[test]
    fn data_tokens_concatenate_into_one_node() {
        // "QUJD" (ABC) twice → one Data node holding "ABCABC".
        let tree = parse_input("// <( DATA QUJD )>\n// <( DATA QUJD )>\n").unwrap();
        match &tree[0] {
            TextNode::Data(d) => assert_eq!(d.as_slice(), b"ABCABC"),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn plain_lines_fold_into_a_single_node() {
        let tree = parse_input("one\ntwo\nthree\n").unwrap();
        assert_eq!(tree.len(), 1, "expected folded Plain, got {tree:?}");
        match &tree[0] {
            TextNode::Plain(s) => assert_eq!(s, "one\ntwo\nthree"),
            other => panic!("expected Plain, got {other:?}"),
        }
    }

    #[test]
    fn directive_after_plain_starts_a_new_plain_run() {
        // A directive interrupts the Plain run; following plain lines
        // open a fresh node (not appended to the pre-directive one).
        let tree = parse_input("before\n// <( STORED W h )>\nafter\n").unwrap();
        assert_eq!(tree.len(), 3, "got {tree:?}");
        assert!(matches!(&tree[0], TextNode::Plain(s) if s == "before"));
        assert!(matches!(&tree[1], TextNode::Stored { .. }));
        assert!(matches!(&tree[2], TextNode::Plain(s) if s == "after"));
    }

    #[test]
    fn chain_directive_collects_extfields() {
        let tree = parse_input("// <( CHAIN parents:ab signer:ed25519:9f )>\n").unwrap();
        match &tree[0] {
            TextNode::Chain { extfields } => {
                assert_eq!(extfields.get("parents").map(String::as_str), Some("ab"));
                assert_eq!(
                    extfields.get("signer").map(String::as_str),
                    Some("ed25519:9f")
                );
            }
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    #[test]
    fn empty_directive_line_is_ignored() {
        // `// <( )>` has no keyword → skipped without a node.
        let tree = parse_input("// <( )>\nplain\n").unwrap();
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn encrypted_multiline_form_collects_data_child() {
        let tree = parse_input(
            "// <( ENCRYPTED W cipher:aes-256-siv )>\n// <( DATA QUJD )>\n// <( END W )>\n",
        )
        .unwrap();
        match &tree[0] {
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => {
                assert_eq!(keyw, "W");
                assert_eq!(
                    extfields.get("cipher").map(String::as_str),
                    Some("aes-256-siv")
                );
                assert!(matches!(&txt[0], TextNode::Data(_)));
            }
            other => panic!("expected Encrypted, got {other:?}"),
        }
    }
}
