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

pub fn parse<R>(buf_in: R, paops: &mut ParseOps) -> Result<TextTree>
where
    R: BufRead,
{
    if paops.max_depth != 0 && paops.runtime.level > paops.max_depth {
        return Err(Error::Msg("Maximum recursion depth!".into()));
    }

    let mut text = Vec::new();
    let mut lineno = 0;
    let mut pstack = Vec::new();

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

        let mut trimmed = line.trim().replacen(&paops.separators.left, "", 1);
        if !trimmed.ends_with(&paops.separators.right) {
            return Err(parse_error(
                paops,
                lineno,
                &line,
                format!("Right separator '{}' missing.", paops.separators.right),
            ));
        }
        let i = trimmed.len() - paops.separators.right.len();
        trimmed.truncate(i);
        let cmd: Vec<&str> = trimmed.split_whitespace().collect();
        if cmd.is_empty() {
            continue;
        }

        let parsed = match Command::from_keyword(cmd[0]) {
            Some(c) => c,
            None => {
                return Err(parse_error(
                    paops,
                    lineno,
                    &line,
                    format!("Unknown section '{}'.", cmd[0]),
                ));
            }
        };

        let rest = &cmd[1..];
        match parsed {
            Command::Data => parse_data(rest, &line, lineno, paops, &mut text)?,
            Command::Begin => parse_begin(rest, &line, lineno, paops, &mut pstack, &mut text)?,
            Command::Encrypted => {
                parse_encrypted(rest, &line, lineno, paops, &mut pstack, &mut text)?
            }
            Command::End => parse_end(rest, &line, lineno, paops, &mut pstack, &mut text)?,
            Command::Stored => parse_stored(rest, &line, lineno, paops, &mut text)?,
            Command::Chain => parse_chain(rest, &line, lineno, paops, &mut text)?,
            // Reserved keywords (TODOs 19/25). Parser support lands
            // in follow-up PRs; for now, encountering one is a clean
            // parse error so users know the directive exists but
            // isn't wired up yet.
            Command::Conflict | Command::Include => {
                return Err(parse_error(
                    paops,
                    lineno,
                    &line,
                    format!(
                        "{:?} directive not yet implemented (reserved keyword)",
                        parsed
                    ),
                ));
            }
        }
    }

    if !pstack.is_empty() {
        for top in pstack.into_iter().rev() {
            match top {
                TextNode::BeginEnd { keyw, .. } => {
                    eprintln!("Parse: BEGIN {} without END.", keyw);
                }
                TextNode::Encrypted { keyw, .. } => {
                    eprintln!("Parse: ENCRYPTED {} without END.", keyw);
                }
                _ => {}
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
    pstack: &mut Vec<TextNode>,
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
    pstack.push(TextNode::BeginEnd {
        keyw: cmd[0].to_owned(),
        txt: text.to_vec(),
    });
    text.clear();
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
    pstack: &mut Vec<TextNode>,
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
            pstack.push(TextNode::Encrypted {
                keyw: cmd[0].to_owned(),
                txt: text.to_vec(),
                extfields,
            });
            text.clear();
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
    pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<()> {
    if cmd.len() > 1 {
        return Err(parse_error(paops, lineno, line, "Unknown padding in END."));
    }

    match pstack.pop() {
        Some(TextNode::BeginEnd { keyw, txt }) => {
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
                txt: text.to_vec(),
            };
            *text = txt;
            text.push(node);
            paops.runtime.level -= 1;
            Ok(())
        }
        Some(TextNode::Encrypted {
            keyw,
            txt,
            extfields,
        }) => {
            if keyw != cmd[0] {
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
                        txt: text.to_vec(),
                        extfields,
                    };
                    *text = txt;
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
        _ => Err(parse_error(
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
