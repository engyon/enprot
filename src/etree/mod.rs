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

//! EPT parsing, transformation, and writing. The public surface is the
//! `TextNode` enum, the `TextTree` type, the `ParseOps` config struct,
//! and the three entry points: `parse`, `transform`, `tree_write`.
//!
//! The implementation is split across submodules:
//!
//! - `mod parse` — line-oriented reader + per-command parsers.
//! - `mod transform` — applies the operation sets to a tree.
//! - `mod write` — unparser back to text.
//! - `mod blob` — in-memory round-trip helpers.
//!
//! All public items remain re-exported here so external callers
//! (`use crate::etree::*;`) still see the same names.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::consts;
use crate::crypto::CryptoPolicy;
use crate::error::{Error, Result};
use crate::pbkdf::PBKDFCache;

mod parse;
mod transform;
mod write;

mod blob;

pub use blob::{blob_to_tree, tree_to_blob};
pub use parse::parse;
pub use transform::transform;
pub use write::tree_write;

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

pub struct Separators {
    pub left: String,
    pub right: String,
}

pub struct Transforms {
    pub store: HashSet<String>,
    pub fetch: HashSet<String>,
    pub encrypt: HashSet<String>,
    pub decrypt: HashSet<String>,
}

pub struct CryptoConfig {
    pub policy: Box<dyn CryptoPolicy>,
    pub pbkdfopts: PBKDFOptions,
    pub cipheropts: CipherOptions,
    pub rng: Option<botan::RandomNumberGenerator>,
    pub pbkdf_cache: Option<PBKDFCache>,
}

pub struct ParseOps {
    pub max_depth: usize,
    pub separators: Separators,
    pub transforms: Transforms,
    pub passwords: HashMap<String, String>,
    pub fname: String,
    pub casdir: PathBuf,
    pub verbose: bool,
    pub crypto: CryptoConfig,
    pub level: usize,
}

impl ParseOps {
    pub fn new(policy: Box<dyn CryptoPolicy>) -> Result<ParseOps> {
        let rng = botan::RandomNumberGenerator::new().map_err(Error::botan)?;
        let pbkdfopts = PBKDFOptions::new(&*policy);
        let cipheropts = CipherOptions::new(&*policy);
        Ok(ParseOps {
            max_depth: consts::DEFAULT_MAX_DEPTH,
            separators: Separators {
                left: consts::DEFAULT_LEFT_SEP.to_string(),
                right: consts::DEFAULT_RIGHT_SEP.to_string(),
            },
            transforms: Transforms {
                store: HashSet::new(),
                fetch: HashSet::new(),
                encrypt: HashSet::new(),
                decrypt: HashSet::new(),
            },
            passwords: HashMap::new(),
            fname: String::new(),
            casdir: Path::new("").to_path_buf(),
            verbose: false,
            level: 0,
            crypto: CryptoConfig {
                policy,
                pbkdfopts,
                cipheropts,
                rng: Some(rng),
                pbkdf_cache: Some(Vec::new()),
            },
        })
    }
}

pub type TextTree = Vec<TextNode>;

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
pub(crate) enum Command {
    Begin,
    End,
    Data,
    Stored,
    Encrypted,
}

impl Command {
    pub(crate) fn from_keyword(kw: &str) -> Option<Self> {
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

pub(crate) fn parse_error(
    paops: &ParseOps,
    lineno: i32,
    line: &str,
    msg: impl Into<String>,
) -> Error {
    Error::Parse {
        file: paops.fname.clone(),
        lineno,
        msg: msg.into() + "\n" + line,
    }
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
        paops.transforms.store.insert("noexist".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        assert_eq!(intree, outtree);
    }

    #[test]
    fn transform_test_ept_store_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.transforms.store.insert("Agent_007".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
        let blob = tree_to_blob(&outtree, &mut paops).unwrap();
        parse(BufReader::new(&blob[..]), &mut paops).unwrap();
    }

    #[test]
    fn transform_test_ept_fetch_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.transforms.fetch.insert("Agent_007".to_string());
        let _outtree = transform(&intree, &mut paops).unwrap();
    }

    #[test]
    fn transform_test_ept_encrypt_agent007() {
        let (intree, mut paops, _casdir) = parse_ept("sample/test.ept");
        paops.transforms.encrypt.insert("Agent_007".to_string());
        paops
            .passwords
            .insert("Agent_007".to_string(), "bond".to_string());
        let outtree = transform(&intree, &mut paops).unwrap();
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
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
        paops.fname = "<test>".into();
        let input = "// <( )>\n";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        assert!(tree.is_empty());
    }
}
