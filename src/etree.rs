// Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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

extern crate base64;
extern crate botan;

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::prelude::*;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use cas;
use consts;
use prot;

pub struct PBKDFOptions {
    pub alg: String,                            // algorithm name
    pub pbkdf2_hash: Option<String>,            // hash alg to use when alg is PBKDF2
    pub saltlen: usize,                         // desired salt length
    pub salt: Option<Vec<u8>>,                  // salt (randomly generated if None)
    pub msec: Option<u32>,                      // desired millis count to determine KDF params
    pub params: Option<HashMap<String, usize>>, // KDF-specific params (if provided)
}

impl PBKDFOptions {
    pub fn new() -> PBKDFOptions {
        PBKDFOptions {
            alg: consts::DEFAULT_PBKDF_ALG.to_string(),
            saltlen: consts::DEFAULT_PBKDF_SALT_LEN,
            salt: None,
            msec: Some(consts::DEFAULT_PBKDF_MSEC),
            pbkdf2_hash: None,
            params: None,
        }
    }
}

// parse operations

pub struct ParseOps {
    pub left_sep: String,                          // left separator
    pub right_sep: String,                         // right separator
    pub store: HashSet<String>,                    // keywords to store
    pub fetch: HashSet<String>,                    // keywords to fetch
    pub encrypt: HashSet<String>,                  // keywords to encrypt
    pub decrypt: HashSet<String>,                  // keywords to decrypt
    pub passwords: HashMap<String, String>,        // passwords
    pub fname: String,                             // file name being parsed
    pub casdir: PathBuf,                           // directory for cas objects
    pub verbose: bool,                             // verbose output to stdout
    pub rng: Option<botan::RandomNumberGenerator>, // RNG to use
    pub pbkdf: PBKDFOptions,                       // the PBKDF options
    level: isize,                                  // current recursion level
}

impl ParseOps {
    pub fn new() -> ParseOps {
        ParseOps {
            left_sep: consts::DEFAULT_LEFT_SEP.to_string(),
            right_sep: consts::DEFAULT_RIGHT_SEP.to_string(),
            store: HashSet::new(),
            fetch: HashSet::new(),
            encrypt: HashSet::new(),
            decrypt: HashSet::new(),
            passwords: HashMap::new(),
            fname: "".to_string(),
            casdir: Path::new("").to_path_buf(),
            level: 0,
            verbose: false,
            rng: Some(botan::RandomNumberGenerator::new().unwrap()),
            pbkdf: PBKDFOptions::new(),
        }
    }
}

const MAX_DEPTH: isize = 100; // at least bail out of infinite loop
const DATA_BYTES_PER_LINE: usize = 48; // that's 64 characters

// the actual tree

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
        pbkdf: Option<String>, // PBKDF PHC string
    },
    BeginEnd {
        keyw: String,
        txt: TextTree,
    },
}

type Parser = fn(
    &[&str],
    &String,
    i32,
    &mut ParseOps,
    &mut Vec<TextNode>,
    &mut Vec<TextNode>,
) -> Result<(), &'static str>;

fn parse_data(
    cmd: &[&str],
    line: &String,
    lineno: i32,
    paops: &mut ParseOps,
    _pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<(), &'static str> {
    for i in 0..cmd.len() {
        let mut data = match base64::decode(cmd[i]) {
            Ok(data) => data,
            Err(e) => {
                eprintln!(
                    "Parse: Error decoding base64.\n\
                     Parse: '{}': {}\n\
                     {}:{}:{}",
                    cmd[i], e, paops.fname, lineno, line
                );
                return Err("Parse error");
            }
        };

        // combine with previous
        if let Some(TextNode::Data(last)) = text.last_mut() {
            last.append(&mut data);
        } else {
            text.push(TextNode::Data(data));
        }
    }
    return Ok(());
}

fn parse_begin(
    cmd: &[&str],
    line: &String,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<(), &'static str> {
    if cmd.len() != 1 {
        eprintln!(
            "Parse: BEGIN needs a single keyword.\n\
             {}:{}:{}",
            paops.fname, lineno, line
        );
        return Err("Parse error");
    }
    paops.level += 1;
    pstack.push(TextNode::BeginEnd {
        keyw: cmd[0].to_owned(),
        txt: text.to_vec(),
    });
    text.clear();
    Ok(())
}

fn parse_encrypted(
    cmd: &[&str],
    line: &String,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<(), &'static str> {
    // parse all extended fields, such as pbkdf:
    let mut extfields: HashMap<String, String> = HashMap::new();
    for field in cmd.iter().rev() {
        if field.find(':') == None {
            // extended fields always come at the end
            break;
        }
        let fields = field.splitn(2, ':').collect::<Vec<&str>>();
        let key = fields[0];
        let value = fields[1];
        if extfields.contains_key(key) {
            return Err("Duplicate extended field");
        }
        extfields.insert(key.to_string(), value.to_string());
    }
    let param_count = cmd.len() - extfields.len();
    let pbkdf: Option<String> = extfields.remove("pbkdf");
    if !extfields.is_empty() {
        return Err("Unrecognized extended field(s) present");
    }
    match param_count {
        1 => {
            // immediate data
            // <( ENCRYPTED Agent_007 )>
            // <( ENCRYPTED Agent_007 pbkdf:... )>
            paops.level += 1;
            pstack.push(TextNode::Encrypted {
                keyw: cmd[0].to_owned(),
                txt: text.to_vec(),
                pbkdf,
            });
            text.clear();
            return Ok(());
        }
        2 => {
            // CAS parameter
            // <( ENCRYPTED Agent_007 7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2 )>
            // <( ENCRYPTED Agent_007 7a8da017c0fe671ba16f4bc55b884444e708849290d8366f19c552c90950b8c2 pbkdf:... )>
            if cmd[1].len() != 64 {
                return Err("Invalid CAS identifier");
            }
            let node = vec![TextNode::Stored {
                keyw: "ct".to_string(),
                cas: cmd[1].to_string(),
            }];
            text.push(TextNode::Encrypted {
                keyw: cmd[0].to_string(),
                txt: node,
                pbkdf,
            });
        }
        _ => {
            eprintln!(
                "Parse: ENCRYPTED has wrong number of \
                 parameters ({}).\n{}:{}:{}",
                param_count, paops.fname, lineno, line
            );
            return Err("Parse error");
        }
    }
    return Ok(());
}

fn parse_end(
    cmd: &[&str],
    line: &String,
    lineno: i32,
    paops: &mut ParseOps,
    pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<(), &'static str> {
    if cmd.len() > 1 {
        eprintln!(
            "Parse: Unknown padding in END.\n{}:{}:{}",
            paops.fname, lineno, line
        );
        return Err("Parse error");
    }
    match pstack.pop() {
        Some(TextNode::BeginEnd { keyw, txt }) => {
            // keyword mismatch ?
            if cmd.len() >= 1 && keyw != cmd[0] {
                eprintln!(
                    "Parse: END mismatch (expected '{}').\n\
                     {}:{}:{}",
                    keyw, paops.fname, lineno, line
                );
                return Err("Parse error");
            }

            let node = TextNode::BeginEnd {
                keyw: keyw,
                txt: text.to_vec(),
            };
            *text = txt;
            text.push(node);
            paops.level -= 1;
        }
        Some(TextNode::Encrypted { keyw, txt, pbkdf }) => {
            // keyword mismatch ?
            if keyw != cmd[0] {
                eprintln!(
                    "Parse: END mismatch (expected '{}').\n\
                     {}:{}:{}",
                    keyw, paops.fname, lineno, line
                );
                return Err("Parse error");
            }
            // check that the contents are right type
            if text.len() != 1 {
                eprintln!(
                    "Parse: {} elements in encrypted {} \
                     (must be a single DATA or STORED).\n{}:{}:{}",
                    text.len(),
                    keyw,
                    paops.fname,
                    lineno,
                    line
                );
                return Err("Parse error");
            }
            match text[0] {
                TextNode::Data(_) | TextNode::Stored { .. } => {
                    let node = TextNode::Encrypted {
                        keyw: keyw,
                        txt: text.to_vec(),
                        pbkdf,
                    };
                    *text = txt;
                    text.push(node);
                    paops.level -= 1;
                }
                _ => {
                    eprintln!(
                        "Parse: not DATA or STORED \
                         element in encrypted {}.\n{}:{}:{}",
                        keyw, paops.fname, lineno, line
                    );
                    return Err("Parse error");
                }
            }
        }
        _ => {
            eprintln!(
                "Parse: END without a start clause.\n{}:{}:{}",
                paops.fname, lineno, line
            );
            return Err("Parse error");
        }
    }
    Ok(())
}

fn parse_stored(
    cmd: &[&str],
    line: &String,
    lineno: i32,
    paops: &mut ParseOps,
    _pstack: &mut Vec<TextNode>,
    text: &mut Vec<TextNode>,
) -> Result<(), &'static str> {
    if cmd.len() != 2 {
        eprintln!(
            "Parse: STORED needs two parameters.\n{}:{}:{}",
            paops.fname, lineno, line
        );
        return Err("Parse error");
    }
    text.push(TextNode::Stored {
        keyw: cmd[0].to_owned(),
        cas: cmd[1].to_owned(),
    });
    Ok(())
}

pub fn parse<R>(buf_in: R, paops: &mut ParseOps) -> Result<TextTree, &'static str>
where
    R: BufRead,
{
    if paops.level > MAX_DEPTH {
        panic!("Maximum recursion depth!");
    }

    let mut text = Vec::new(); // the vector of TextNodes
    let mut lineno = 0; // line number in source
    let mut pstack = Vec::new(); // stack

    for line_in in buf_in.lines() {
        let line = line_in.expect("read error");
        lineno += 1;

        if !line.trim_start().starts_with(&paops.left_sep) {
            // combine with previous
            if let Some(TextNode::Plain(last)) = text.last_mut() {
                last.push('\n');
                *last += &line;
                continue;
            }

            text.push(TextNode::Plain(line.clone()));
            continue;
        }

        // we have a command
        let mut trimmed = line.trim().replacen(&paops.left_sep, "", 1);

        // create a vector out of it
        if !trimmed.ends_with(&paops.right_sep) {
            eprintln!(
                "Parse: Right separator '{}' missing.\n\
                 {}:{}:{}",
                paops.right_sep, paops.fname, lineno, line
            );
            return Err("Parse error");
        }

        let i = trimmed.len() - paops.right_sep.len();
        trimmed.truncate(i);
        let cmd: Vec<&str> = trimmed.split_whitespace().collect();

        let mut cmd_parsers: HashMap<&str, Parser> = HashMap::new();
        cmd_parsers.insert("DATA", parse_data);
        cmd_parsers.insert("BEGIN", parse_begin);
        cmd_parsers.insert("ENCRYPTED", parse_encrypted);
        cmd_parsers.insert("END", parse_end);
        cmd_parsers.insert("STORED", parse_stored);
        match cmd_parsers.get(cmd[0]) {
            Some(parser) => {
                parser(&cmd[1..], &line, lineno, paops, &mut pstack, &mut text)?;
                continue;
            }
            _ => {
                eprintln!(
                    "Parse: Unknown section '{}' at\n{}:{}:{}",
                    cmd[0], paops.fname, lineno, line
                );
                return Err("Parse error");
            }
        }
    }

    if pstack.len() > 0 {
        loop {
            match pstack.pop() {
                Some(TextNode::BeginEnd { keyw, txt: _ }) => {
                    eprintln!("Parse: BEGIN {} without END.", keyw);
                }
                Some(TextNode::Encrypted {
                    keyw,
                    txt: _,
                    pbkdf: _,
                }) => {
                    eprintln!("Parse: ENCRYPTED {} without END.", keyw);
                }
                _ => return Err("Unexpected end"),
            }
        }
    }

    Ok(text)
}

// recursive unparser

pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) {
    for elem in text {
        match elem {
            // Plain chunk of text
            TextNode::Plain(line) => {
                writeln!(outw, "{}", line).unwrap();
            }

            // BEGIN-END block
            TextNode::BeginEnd { keyw, txt } => {
                writeln!(
                    outw,
                    "{} BEGIN {} {}",
                    paops.left_sep, keyw, paops.right_sep
                )
                .unwrap();
                paops.level += 1;
                tree_write(outw, txt, paops);
                paops.level -= 1;
                writeln!(outw, "{} END {} {}", paops.left_sep, keyw, paops.right_sep).unwrap();
            }

            // ENCRYPTED block
            TextNode::Encrypted {
                keyw,
                txt,
                ref pbkdf,
            } => {
                if let TextNode::Stored { keyw: _, ref cas } = txt[0] {
                    if *pbkdf == None {
                        writeln!(
                            outw,
                            "{} ENCRYPTED {} {} {}",
                            paops.left_sep, keyw, cas, paops.right_sep
                        )
                        .unwrap();
                    } else {
                        writeln!(
                            outw,
                            "{} ENCRYPTED {} {} pbkdf:{} {}",
                            paops.left_sep,
                            keyw,
                            cas,
                            &pbkdf.clone().unwrap(),
                            paops.right_sep
                        )
                        .unwrap();
                    }
                } else {
                    if *pbkdf == None {
                        writeln!(
                            outw,
                            "{} ENCRYPTED {} {}",
                            paops.left_sep, keyw, paops.right_sep
                        )
                        .unwrap();
                    } else {
                        writeln!(
                            outw,
                            "{} ENCRYPTED {} pbkdf:{} {}",
                            paops.left_sep,
                            keyw,
                            &pbkdf.clone().unwrap(),
                            paops.right_sep
                        )
                        .unwrap();
                    }
                    paops.level += 1;
                    tree_write(outw, txt, paops);
                    paops.level -= 1;
                    writeln!(outw, "{} END {} {}", paops.left_sep, keyw, paops.right_sep).unwrap();
                }
            }

            // STORED
            TextNode::Stored { keyw, cas } => {
                writeln!(
                    outw,
                    "{} STORED {} {} {}",
                    paops.left_sep, keyw, cas, paops.right_sep
                )
                .unwrap();
            }
            // DATA
            TextNode::Data(data) => {
                for line in data.chunks(DATA_BYTES_PER_LINE) {
                    writeln!(
                        outw,
                        "{} DATA {} {}",
                        paops.left_sep,
                        base64::encode(line),
                        paops.right_sep
                    )
                    .unwrap();
                }
            }
        }
    }
}

// perform ops

pub fn transform(text_in: &TextTree, mut paops: &mut ParseOps) -> Result<TextTree, &'static str> {
    let mut text_out = Vec::new();

    if paops.level > MAX_DEPTH {
        panic!("Maximum recursion depth!");
    }

    for elem in text_in {
        match elem {
            // BEGIN-END
            TextNode::BeginEnd { ref keyw, ref txt } => {
                // encrypt it ?
                if paops.encrypt.contains(keyw) {
                    // get blob
                    let pt = tree_to_blob(&txt, paops);

                    // get password
                    let (newpass, pass) = match paops.passwords.get(keyw) {
                        Some(pass) => (false, pass.to_string()),
                        None => (true, prot::get_password(&keyw, true)),
                    };
                    if newpass {
                        paops
                            .passwords
                            .insert(keyw.clone().to_string(), pass.clone());
                    }

                    // encrypt
                    let (ct, pbkdf) = prot::encrypt(pt, &pass, &paops.rng, &paops.pbkdf)?;

                    // also store it (store at CAS) ?
                    let node = if paops.store.contains(keyw) {
                        let hexhash = cas::save(ct, paops)?;
                        vec![TextNode::Stored {
                            keyw: "ct".to_string(),
                            cas: hexhash,
                        }]
                    } else {
                        vec![TextNode::Data(ct)]
                    };
                    text_out.push(TextNode::Encrypted {
                        keyw: keyw.to_string(),
                        txt: node,
                        pbkdf,
                    });
                    continue;
                }

                // just store it without encryption ?
                if paops.store.contains(keyw) {
                    let blob = tree_to_blob(&txt, paops);
                    let hexhash = cas::save(blob, paops)?;
                    text_out.push(TextNode::Stored {
                        keyw: keyw.to_string(),
                        cas: hexhash,
                    });
                    continue;
                };

                // just recursion
                paops.level += 1;
                let block = transform(&txt.to_vec(), paops)?;
                paops.level -= 1;

                text_out.push(TextNode::BeginEnd {
                    keyw: keyw.to_string(),
                    txt: block,
                });
                continue;
            }

            // ENCRYPTED
            TextNode::Encrypted {
                ref keyw,
                ref txt,
                ref pbkdf,
            } => {
                // decrypt it
                if paops.decrypt.contains(keyw) {
                    // get ciphertext
                    let ct = match txt[0] {
                        TextNode::Data(ref data) => data.to_vec(),
                        TextNode::Stored {
                            keyw: _,
                            cas: ref hexhash,
                        } => cas::load(&hexhash, paops)?,
                        _ => panic!("No data in ENCRYPTED."),
                    };

                    // get password
                    let (newpass, pass) = match paops.passwords.get(keyw) {
                        Some(pass) => (false, pass.to_string()),
                        None => (true, prot::get_password(keyw, false)),
                    };
                    if newpass {
                        paops
                            .passwords
                            .insert(keyw.clone().to_string(), pass.clone());
                    }

                    // decrypt
                    let pt = match prot::decrypt(ct, &pass, pbkdf) {
                        Ok(ct) => ct.to_vec(),
                        Err(e) => {
                            eprintln!("Error decrypting {}: {}.", &keyw, e);
                            return Err(e);
                        }
                    };

                    // parse to tree
                    let subtree = blob_to_tree(pt, "decrypted".to_string(), &mut paops)?;
                    text_out.push(TextNode::BeginEnd {
                        keyw: keyw.to_string(),
                        txt: subtree,
                    });
                    continue;
                } else {
                    // store (store) ciphertext
                    if paops.store.contains(keyw) {
                        let hexhash = match txt[0] {
                            TextNode::Data(ref data) => cas::save(data.to_vec(), paops)?,
                            TextNode::Stored {
                                keyw: _,
                                cas: ref hexhash,
                            } => hexhash.to_string(),
                            _ => panic!("No data in ENCRYPTED."),
                        };
                        let node = vec![TextNode::Stored {
                            keyw: "ct".to_string(),
                            cas: hexhash,
                        }];
                        text_out.push(TextNode::Encrypted {
                            keyw: keyw.to_string(),
                            txt: node,
                            pbkdf: None,
                        });
                        continue;
                    }

                    // fetch (include) ciphertext
                    if paops.fetch.contains(keyw) {
                        let ct = match txt[0] {
                            TextNode::Data(ref data) => data.to_vec(),
                            TextNode::Stored {
                                keyw: _,
                                cas: ref hexhash,
                            } => cas::load(&hexhash, paops)?,
                            _ => panic!("No data in ENCRYPTED."),
                        };
                        let node = vec![TextNode::Data(ct)];

                        text_out.push(TextNode::Encrypted {
                            keyw: keyw.to_string(),
                            txt: node,
                            pbkdf: None,
                        });
                        continue;
                    };
                }

                text_out.push(elem.clone());
            }

            // STORED
            TextNode::Stored { ref keyw, ref cas } => {
                // fetch it ?
                if paops.fetch.contains(keyw) {
                    let blob = cas::load(&cas, paops)?;
                    let subtree = blob_to_tree(blob, cas.to_string(), paops)?;
                    text_out.push(TextNode::BeginEnd {
                        keyw: keyw.to_string(),
                        txt: subtree,
                    });
                    continue;
                }

                text_out.push(elem.clone());
            }

            // don't care, just copy
            _ => text_out.push(elem.clone()),
        }
    }
    Ok(text_out)
}

// convenience functions

fn blob_to_tree(
    data: Vec<u8>,
    path: String,
    mut paops: &mut ParseOps,
) -> Result<TextTree, &'static str> {
    paops.fname = path.clone();
    let tree = parse(Cursor::new(data), &mut paops)?;
    Ok(tree)
}

fn tree_to_blob(text: &TextTree, mut paops: &mut ParseOps) -> Vec<u8> {
    let mut blob = Vec::new();
    tree_write(&mut blob, text, &mut paops);
    blob
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::tempdir;
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::BufReader;
    use std::str;

    fn parse_ept(ept_file: &str) -> (TextTree, ParseOps, tempfile::TempDir) {
        let casdir = tempdir().unwrap();
        let mut paops = ParseOps {
            fname: ept_file.to_string(),
            casdir: casdir.path().to_path_buf(),
            ..ParseOps::new()
        };
        let tree = parse(
            BufReader::new(File::open(ept_file.to_string()).unwrap()),
            &mut paops,
        )
        .unwrap();
        (tree, paops, casdir)
    }

    // test that we can call transform on this file without any options
    // set and it will remain unchanged
    #[test]
    fn transform_test_ept_unchanged() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        let outtree = transform(&intree, &mut paops).unwrap();
        assert_eq!(intree, outtree);
    }

    // test that a store with a non-existant keyword does not change
    // anything
    #[test]
    fn transform_test_ept_store_unchanged() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.store.insert("noexist".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        assert_eq!(intree, outtree);
    }

    // test that we can do a basic store operation on this file
    #[test]
    fn transform_test_ept_store_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.store.insert("Agent_007".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        // re-parse
        parse(
            BufReader::new(&tree_to_blob(&outtree, &mut paops)[..]),
            &mut paops,
        )
        .unwrap();

        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("test-data/test-store-agent007.ept").unwrap()
        );
        assert_eq!(
            str::from_utf8(
                &cas::load(
                    "d094e230861eb0ab43b895b8ecdeeb9e3a7e4a88239341a81da832ac181feaab",
                    &mut paops,
                )
                .unwrap(),
            )
            .unwrap(),
            "James Bond\n",
        );
        assert_eq!(
            str::from_utf8(
                &cas::load(
                    "575d69f5b0034279bc3ef164e94287e6366e9df76729895a302a66a8817cf306",
                    &mut paops,
                )
                .unwrap(),
            )
            .unwrap(),
            "Super secret line 3\n"
        );
    }

    // test that we can do a basic fetch operation on this file
    #[test]
    fn transform_test_ept_fetch_geheim() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        // store
        paops.store.insert("GEHEIM".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        // re-parse
        parse(
            BufReader::new(&tree_to_blob(&outtree, &mut paops)[..]),
            &mut paops,
        )
        .unwrap();

        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("test-data/test-store-geheim.ept").unwrap()
        );
        assert_eq!(
                str::from_utf8(
                    &cas::load(
                        "cea67c3ef34ff899793b557e9178c1b97bbcfe9722df2f6d35d2d0c91d2c1fe4",
                        &mut paops,
                    )
                    .unwrap(),
                )
                .unwrap(),
                "Secret line 1\nSecret line 2\n// <( BEGIN Agent_007 )>\nJames Bond\n// <( END Agent_007 )>\n"
            );
        // fetch
        paops.store.clear();
        paops.fetch.insert("GEHEIM".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("sample/test.ept").unwrap()
        );
    }

    // test that we can do a basic encrypt and decrypt on this file
    #[test]
    fn transform_test_ept_encrypt_decrypt_geheim() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.pbkdf.alg = "legacy".to_string();
        // encrypt
        paops.encrypt.insert("GEHEIM".to_string());
        paops
            .passwords
            .insert("GEHEIM".to_string(), "password".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        // re-parse
        parse(
            BufReader::new(&tree_to_blob(&outtree, &mut paops)[..]),
            &mut paops,
        )
        .unwrap();

        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("test-data/test-encrypt-geheim.ept").unwrap()
        );
        // decrypt
        paops.encrypt.clear();
        paops.decrypt.insert("GEHEIM".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("sample/test.ept").unwrap()
        );
    }

    // test that we can do a basic encrypt & store operation on this file
    #[test]
    fn transform_test_ept_encrypt_store_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.pbkdf.alg = "legacy".to_string();
        // encrypt & store
        paops.encrypt.insert("Agent_007".to_string());
        paops.store.insert("Agent_007".to_string());
        paops
            .passwords
            .insert("Agent_007".to_string(), "password".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        // re-parse
        parse(
            BufReader::new(&tree_to_blob(&outtree, &mut paops)[..]),
            &mut paops,
        )
        .unwrap();

        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("test-data/test-encrypt-store-agent007.ept").unwrap()
        );
        // decrypt
        paops.encrypt.clear();
        paops.store.clear();
        paops.decrypt.insert("Agent_007".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        let buf = tree_to_blob(&outtree, &mut paops);
        assert_eq!(
            str::from_utf8(&buf).unwrap(),
            &fs::read_to_string("sample/test.ept").unwrap()
        );
    }
}
