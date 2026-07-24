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

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::prelude::*;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use crate::cas;
use crate::consts;
use crate::crypto::CryptoPolicy;
use crate::error::{Error, Result};
use crate::password;
use crate::pbkdf::PBKDFCache;
use crate::prot;
use crate::utils;

pub struct PBKDFOptions {
    pub alg: String,
    pub saltlen: usize,
    pub salt: Option<Vec<u8>>,
    pub msec: Option<u32>,
    pub params: Option<BTreeMap<String, usize>>,
}

impl PBKDFOptions {
    pub fn new(policy: &dyn CryptoPolicy) -> PBKDFOptions {
        PBKDFOptions {
            alg: policy.default_pbkdf_alg(),
            saltlen: policy.default_pbkdf_salt_length(),
            salt: None,
            msec: Some(policy.default_pbkdf_millis()),
            params: None,
        }
    }
}

pub struct CipherOptions {
    pub alg: String,
    pub iv: Option<Vec<u8>>,
}

impl CipherOptions {
    pub fn new(policy: &dyn CryptoPolicy) -> CipherOptions {
        CipherOptions {
            alg: policy.default_cipher_alg(),
            iv: None,
        }
    }
}

pub struct ParseOps {
    pub max_depth: usize,
    pub left_sep: String,
    pub right_sep: String,
    pub store: HashSet<String>,
    pub fetch: HashSet<String>,
    pub encrypt: HashSet<String>,
    pub decrypt: HashSet<String>,
    pub passwords: HashMap<String, String>,
    pub fname: String,
    pub casdir: PathBuf,
    pub verbose: bool,
    pub rng: Option<botan::RandomNumberGenerator>,
    pub policy: Box<dyn CryptoPolicy>,
    pub pbkdfopts: PBKDFOptions,
    pub pbkdf_cache: Option<PBKDFCache>,
    pub cipheropts: CipherOptions,
    level: usize,
}

impl ParseOps {
    pub fn new(policy: Box<dyn CryptoPolicy>) -> Result<ParseOps> {
        let rng = botan::RandomNumberGenerator::new().map_err(Error::botan)?;
        Ok(ParseOps {
            max_depth: consts::DEFAULT_MAX_DEPTH,
            left_sep: consts::DEFAULT_LEFT_SEP.to_string(),
            right_sep: consts::DEFAULT_RIGHT_SEP.to_string(),
            store: HashSet::new(),
            fetch: HashSet::new(),
            encrypt: HashSet::new(),
            decrypt: HashSet::new(),
            passwords: HashMap::new(),
            fname: String::new(),
            casdir: Path::new("").to_path_buf(),
            level: 0,
            verbose: false,
            rng: Some(rng),
            pbkdfopts: PBKDFOptions::new(&*policy),
            pbkdf_cache: Some(Vec::new()),
            cipheropts: CipherOptions::new(&*policy),
            policy,
        })
    }
}

const DATA_BYTES_PER_LINE: usize = 48;

type TextTree = Vec<TextNode>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TextNode {
    Plain(String),
    Data(Vec<u8>),
    Stored {
        keyw: String,
        cas: String,
    },
    Encrypted {
        keyw: String,
        txt: TextTree,
        extfields: BTreeMap<String, String>,
    },
    BeginEnd {
        keyw: String,
        txt: TextTree,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Command {
    Begin,
    End,
    Data,
    Stored,
    Encrypted,
}

impl Command {
    fn from_keyword(kw: &str) -> Option<Self> {
        match kw {
            "BEGIN" => Some(Self::Begin),
            "END" => Some(Self::End),
            "DATA" => Some(Self::Data),
            "STORED" => Some(Self::Stored),
            "ENCRYPTED" => Some(Self::Encrypted),
            _ => None,
        }
    }
}

fn parse_error(paops: &ParseOps, lineno: i32, line: &str, msg: impl Into<String>) -> Error {
    Error::Parse {
        file: paops.fname.clone(),
        lineno,
        msg: msg.into() + "\n" + line,
    }
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
    paops.level += 1;
    pstack.push(TextNode::BeginEnd {
        keyw: cmd[0].to_owned(),
        txt: text.to_vec(),
    });
    text.clear();
    Ok(())
}

fn parse_encrypted_extfields(
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
            paops.level += 1;
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
            paops.level -= 1;
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
                    paops.level -= 1;
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

pub fn parse<R>(buf_in: R, paops: &mut ParseOps) -> Result<TextTree>
where
    R: BufRead,
{
    if paops.max_depth != 0 && paops.level > paops.max_depth {
        return Err(Error::Msg("Maximum recursion depth!".into()));
    }

    let mut text = Vec::new();
    let mut lineno = 0;
    let mut pstack = Vec::new();

    for line_in in buf_in.lines() {
        let line = line_in?;
        lineno += 1;

        if !line.trim_start().starts_with(&paops.left_sep) {
            if let Some(TextNode::Plain(last)) = text.last_mut() {
                last.push('\n');
                last.push_str(&line);
                continue;
            }
            text.push(TextNode::Plain(line.clone()));
            continue;
        }

        let mut trimmed = line.trim().replacen(&paops.left_sep, "", 1);
        if !trimmed.ends_with(&paops.right_sep) {
            return Err(parse_error(
                paops,
                lineno,
                &line,
                format!("Right separator '{}' missing.", paops.right_sep),
            ));
        }
        let i = trimmed.len() - paops.right_sep.len();
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
            file: paops.fname.clone(),
            lineno: 0,
            msg: "Unclosed section".into(),
        });
    }

    Ok(text)
}

pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) -> Result<()> {
    for elem in text {
        match elem {
            TextNode::Plain(line) => writeln!(outw, "{}", line)?,
            TextNode::BeginEnd { keyw, txt } => {
                writeln!(
                    outw,
                    "{} BEGIN {} {}",
                    paops.left_sep, keyw, paops.right_sep
                )?;
                paops.level += 1;
                tree_write(outw, txt, paops)?;
                paops.level -= 1;
                writeln!(outw, "{} END {} {}", paops.left_sep, keyw, paops.right_sep)?;
            }
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => {
                write!(outw, "{} ENCRYPTED {}", paops.left_sep, keyw)?;
                if let TextNode::Stored { keyw: _, cas } = &txt[0] {
                    write!(outw, " {}", cas)?;
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.right_sep)?;
                } else {
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.right_sep)?;
                    paops.level += 1;
                    tree_write(outw, txt, paops)?;
                    paops.level -= 1;
                    writeln!(outw, "{} END {} {}", paops.left_sep, keyw, paops.right_sep)?;
                }
            }
            TextNode::Stored { keyw, cas } => {
                writeln!(
                    outw,
                    "{} STORED {} {} {}",
                    paops.left_sep, keyw, cas, paops.right_sep
                )?;
            }
            TextNode::Data(data) => {
                for chunk in data.chunks(DATA_BYTES_PER_LINE) {
                    writeln!(
                        outw,
                        "{} DATA {} {}",
                        paops.left_sep,
                        utils::base64_encode(chunk)?,
                        paops.right_sep
                    )?;
                }
            }
        }
    }
    Ok(())
}

pub fn transform(text_in: &TextTree, paops: &mut ParseOps) -> Result<TextTree> {
    if paops.max_depth != 0 && paops.level > paops.max_depth {
        return Err(Error::Msg("Maximum recursion depth!".into()));
    }
    let mut out = Vec::with_capacity(text_in.len());
    for node in text_in {
        let new_node = match node {
            TextNode::Plain(_) | TextNode::Data(_) => node.clone(),
            TextNode::BeginEnd { .. } => transform_begin_end(node, paops)?,
            TextNode::Encrypted { .. } => transform_encrypted(node, paops)?,
            TextNode::Stored { .. } => transform_stored(node, paops)?,
        };
        out.push(new_node);
    }
    Ok(out)
}

fn transform_begin_end(node: &TextNode, paops: &mut ParseOps) -> Result<TextNode> {
    let (keyw, txt) = match node {
        TextNode::BeginEnd { keyw, txt } => (keyw.clone(), txt.clone()),
        _ => unreachable!(),
    };

    if paops.encrypt.contains(&keyw) {
        paops.level += 1;
        let block = transform(&txt, paops)?;
        paops.level -= 1;

        let pt = tree_to_blob(&block, paops)?;
        let pass = ensure_password(&keyw, paops, true);
        let (ct, extfields) = prot::encrypt(
            pt,
            &pass,
            &mut paops.rng,
            &paops.pbkdfopts,
            &paops.cipheropts,
            &mut paops.pbkdf_cache,
            &*paops.policy,
        )?;

        let inner = if paops.store.contains(&keyw) {
            let hexhash = cas::save(ct, paops)?;
            vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }]
        } else {
            vec![TextNode::Data(ct)]
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: inner,
            extfields,
        });
    }

    if paops.store.contains(&keyw) {
        paops.level += 1;
        let block = transform(&txt, paops)?;
        paops.level -= 1;

        let blob = tree_to_blob(&block, paops)?;
        let hexhash = cas::save(blob, paops)?;
        return Ok(TextNode::Stored { keyw, cas: hexhash });
    }

    paops.level += 1;
    let block = transform(&txt, paops)?;
    paops.level -= 1;
    Ok(TextNode::BeginEnd { keyw, txt: block })
}

fn transform_encrypted(node: &TextNode, paops: &mut ParseOps) -> Result<TextNode> {
    let (keyw, txt, extfields) = match node {
        TextNode::Encrypted {
            keyw,
            txt,
            extfields,
        } => (keyw.clone(), txt.clone(), extfields.clone()),
        _ => unreachable!(),
    };

    if paops.decrypt.contains(&keyw) {
        let ct = match &txt[0] {
            TextNode::Data(data) => data.clone(),
            TextNode::Stored { cas: hexhash, .. } => cas::load(hexhash, paops)?,
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };

        let pass = ensure_password(&keyw, paops, false);
        let pt = match prot::decrypt(
            ct,
            &pass,
            &extfields.get("pbkdf"),
            &extfields.get("cipher"),
            &mut paops.pbkdf_cache,
            &*paops.policy,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error decrypting {}: {}.", &keyw, e);
                return Err(e);
            }
        };

        let mut block = blob_to_tree(pt, "decrypted".to_string(), paops)?;
        paops.level += 1;
        block = transform(&block, paops)?;
        paops.level -= 1;
        return Ok(TextNode::BeginEnd { keyw, txt: block });
    }

    if paops.store.contains(&keyw) {
        let hexhash = match &txt[0] {
            TextNode::Data(data) => cas::save(data.clone(), paops)?,
            TextNode::Stored { cas: hexhash, .. } => hexhash.clone(),
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: hexhash,
            }],
            extfields: BTreeMap::new(),
        });
    }

    if paops.fetch.contains(&keyw) {
        let ct = match &txt[0] {
            TextNode::Data(data) => data.clone(),
            TextNode::Stored { cas: hexhash, .. } => cas::load(hexhash, paops)?,
            _ => return Err(Error::Msg("No data in ENCRYPTED.".into())),
        };
        return Ok(TextNode::Encrypted {
            keyw,
            txt: vec![TextNode::Data(ct)],
            extfields: BTreeMap::new(),
        });
    }

    Ok(node.clone())
}

fn transform_stored(node: &TextNode, paops: &mut ParseOps) -> Result<TextNode> {
    let (keyw, cas) = match node {
        TextNode::Stored { keyw, cas } => (keyw.clone(), cas.clone()),
        _ => unreachable!(),
    };

    if paops.fetch.contains(&keyw) {
        let blob = cas::load(&cas, paops)?;
        let mut block = blob_to_tree(blob, cas.clone(), paops)?;
        paops.level += 1;
        block = transform(&block, paops)?;
        paops.level -= 1;
        return Ok(TextNode::BeginEnd { keyw, txt: block });
    }

    Ok(node.clone())
}

fn ensure_password(keyw: &str, paops: &mut ParseOps, repeat: bool) -> String {
    if let Some(p) = paops.passwords.get(keyw) {
        return p.clone();
    }
    let p = password::get_password(keyw, repeat);
    paops.passwords.insert(keyw.to_string(), p.clone());
    p
}

fn blob_to_tree(data: Vec<u8>, path: String, paops: &mut ParseOps) -> Result<TextTree> {
    paops.fname = path;
    parse(Cursor::new(data), paops)
}

fn tree_to_blob(text: &TextTree, paops: &mut ParseOps) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    tree_write(&mut blob, text, paops)?;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoPolicyDefault;
    use std::fs::File;
    use std::io::BufReader;
    use tempfile::tempdir;

    fn parse_ept(ept_file: &str) -> (TextTree, ParseOps, tempfile::TempDir) {
        let casdir = tempdir().unwrap();
        let mut paops = ParseOps {
            fname: ept_file.to_string(),
            casdir: casdir.path().to_path_buf(),
            ..ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap()
        };
        let tree = parse(BufReader::new(File::open(ept_file).unwrap()), &mut paops).unwrap();
        (tree, paops, casdir)
    }

    #[test]
    fn transform_test_ept_unchanged() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        let outtree = transform(&intree, &mut paops).unwrap();
        assert_eq!(intree, outtree);
    }

    #[test]
    fn transform_test_ept_store_unchanged() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.store.insert("noexist".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        assert_eq!(intree, outtree);
    }

    #[test]
    fn transform_test_ept_store_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.store.insert("Agent_007".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        let blob = tree_to_blob(&outtree, &mut paops).unwrap();
        parse(BufReader::new(&blob[..]), &mut paops).unwrap();
    }

    #[test]
    fn transform_test_ept_fetch_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.fetch.insert("Agent_007".to_string());
        let _outtree = transform(&intree, &mut paops).unwrap();
    }

    #[test]
    fn transform_test_ept_encrypt_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.encrypt.insert("Agent_007".to_string());
        paops
            .passwords
            .insert("Agent_007".to_string(), "bond".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        // re-parse the serialized output to ensure validity
        let blob = tree_to_blob(&outtree, &mut paops).unwrap();
        parse(BufReader::new(&blob[..]), &mut paops).unwrap();
    }

    #[test]
    fn command_enum_recognizes_all_keywords() {
        assert_eq!(Command::from_keyword("BEGIN"), Some(Command::Begin));
        assert_eq!(Command::from_keyword("END"), Some(Command::End));
        assert_eq!(Command::from_keyword("DATA"), Some(Command::Data));
        assert_eq!(Command::from_keyword("STORED"), Some(Command::Stored));
        assert_eq!(Command::from_keyword("ENCRYPTED"), Some(Command::Encrypted));
        assert_eq!(Command::from_keyword("garbage"), None);
    }

    #[test]
    fn empty_command_line_is_skipped() {
        // A line consisting of just separators parses to no command and
        // is silently skipped, matching the original behavior.
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
        paops.fname = "<test>".into();
        let input = "// <( )>\n";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        assert!(tree.is_empty());
    }
}
