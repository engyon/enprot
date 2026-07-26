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

/// Per-invocation mutable state: stuff that changes during a parse
/// or transform pass. Extracted from `ParseOps` to make the
/// runtime-vs-config distinction visible at the type level
/// (TODO.finalize/35).
pub struct RuntimeState {
    /// Current recursion depth (for max-depth enforcement).
    pub level: usize,
    /// File currently being processed (for error messages).
    pub fname: String,
}

/// Chain-anchor production config (TODO.finalize/17). Populated by
/// the CLI layer when `--anchor --signer <priv>` are both supplied.
/// Lives on `ParseOps` so the per-file pipeline can append anchors
/// as it writes outputs.
#[derive(Clone, Debug, Default)]
pub struct AnchorConfig {
    pub enabled: bool,
    pub operation: String,
    pub words: Vec<String>,
    pub signer_priv_pem: Option<String>,
}

impl AnchorConfig {
    pub fn disabled() -> Self {
        AnchorConfig::default()
    }
}

/// IO and observability configuration. Extracted from `ParseOps`
/// alongside `RuntimeState` so the configuration/runtime split is
/// clean: `RuntimeState` mutates per-file, `IoConfig` is set once
/// at startup.
pub struct IoConfig {
    /// CAS directory: where `STORED` blobs live.
    pub casdir: PathBuf,
    /// Verbose output (caller asked for `-v`).
    pub verbose: bool,
    /// Force inline `DATA` blocks on encrypt even when CAS is
    /// available. Restores the pre-42 behavior. Default: false
    /// (CAS-referenced `STORED ct <hash>` is the merge-friendly
    /// default whenever CAS exists). See TODO.roadmap/42.
    pub inline_data: bool,
}

pub struct ParseOps {
    pub max_depth: usize,
    pub separators: Separators,
    pub transforms: Transforms,
    pub passwords: HashMap<String, String>,
    pub crypto: CryptoConfig,
    pub runtime: RuntimeState,
    pub io: IoConfig,
    /// Chain-anchor production config. Default-disabled; populated
    /// by `run()` when the caller passes `--anchor --signer <priv>`.
    /// See TODO.finalize/17.
    pub anchor: AnchorConfig,
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
            crypto: CryptoConfig {
                policy,
                pbkdfopts,
                cipheropts,
                rng: Some(rng),
                pbkdf_cache: Some(Vec::new()),
            },
            runtime: RuntimeState {
                level: 0,
                fname: String::new(),
            },
            io: IoConfig {
                casdir: Path::new("").to_path_buf(),
                verbose: false,
                inline_data: false,
            },
            anchor: AnchorConfig::disabled(),
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
    /// Chain anchor (TODO.finalize/17). Single-line directive using
    /// the same `key:value` extfield pattern as `Encrypted`. The
    /// transform passes ignore `Chain` nodes — they're metadata
    /// about file history, not content to encrypt/store/etc.
    ///
    /// Known extfields (others preserved for forward compatibility):
    /// - `parents` — comma-separated SHA3-256 hex hashes of parent anchors
    /// - `signer` — `<alg>:<fp-hex>` (e.g., `ed25519:9f3a7b…`)
    /// - `ts` — compact RFC 3339 timestamp (`20260725T143000Z`); optional
    /// - `mut` — human-readable mutation description; `+` for spaces; optional
    /// - `payload` — SHA3-256 hex of the file-tree state at this anchor
    /// - `sig` — hex-encoded signature over `parents || signer || ts || payload`
    Chain {
        extfields: BTreeMap<String, String>,
    },
    /// Cross-file DAG reference (TODO.finalize/25). The `hash` is a
    /// CAS blob ID pointing to another EPT file. Resolution and
    /// recursive verification is done by `verify-chain` (not the
    /// parser — the parser just records the reference).
    Include {
        hash: String,
    },
    /// Merge-driver conflict marker (TODO.roadmap/43). Holds both
    /// sides of a conflicting WORD region so the file remains valid
    /// host-language source (the `<<<<<<<` markers git would
    /// otherwise emit aren't valid EPT). `enprot resolve` walks
    /// these and produces a clean tree.
    Conflict {
        keyw: String,
        ours: TextTree,
        theirs: TextTree,
    },
}

/// EPT directive types — one per recognized keyword in the markup.
///
/// Single source of truth for directive names: the parser uses
/// [`Directive::from_keyword`] to dispatch, the writer uses
/// [`Directive::keyword`] to serialize. Adding a new directive type
/// (e.g., `CHAIN`, `CONFLICT`, `INCLUDE`) is one variant plus one
/// match arm in each consumer — OCP-friendly.
///
/// Variants not yet wired into the parser (`Chain`, `Conflict`,
/// `Include`) are present so that downstream code (chain anchors,
/// merge driver, cross-file DAG) can reference them without touching
/// this enum again.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Directive {
    Begin,
    End,
    Data,
    Stored,
    Encrypted,
    /// Chain anchor (TODO.finalize/17). Specified; parser integration
    /// lands in a follow-up PR.
    Chain,
    /// Conflict marker (TODO.finalize/19). Used by the merge driver.
    Conflict,
    /// Mode-switch inside a CONFLICT block (TODO.roadmap/43). Marks
    /// the start of the "ours" side.
    Ours,
    /// Mode-switch inside a CONFLICT block. Marks the start of the
    /// "theirs" side.
    Theirs,
    /// Cross-file DAG reference (TODO.finalize/25).
    Include,
}

impl Directive {
    /// The wire-format keyword (`"BEGIN"`, `"END"`, etc.). Stable,
    /// uppercase, never localized.
    pub fn keyword(self) -> &'static str {
        match self {
            Directive::Begin => "BEGIN",
            Directive::End => "END",
            Directive::Data => "DATA",
            Directive::Stored => "STORED",
            Directive::Encrypted => "ENCRYPTED",
            Directive::Chain => "CHAIN",
            Directive::Conflict => "CONFLICT",
            Directive::Ours => "OURS",
            Directive::Theirs => "THEIRS",
            Directive::Include => "INCLUDE",
        }
    }

    /// Parse a keyword string into a `Directive`. Returns `None` for
    /// unrecognized keywords (caller decides whether that's an error
    /// or a pass-through line).
    pub fn from_keyword(kw: &str) -> Option<Self> {
        match kw {
            "BEGIN" => Some(Directive::Begin),
            "END" => Some(Directive::End),
            "DATA" => Some(Directive::Data),
            "STORED" => Some(Directive::Stored),
            "ENCRYPTED" => Some(Directive::Encrypted),
            "CHAIN" => Some(Directive::Chain),
            "CONFLICT" => Some(Directive::Conflict),
            "OURS" => Some(Directive::Ours),
            "THEIRS" => Some(Directive::Theirs),
            "INCLUDE" => Some(Directive::Include),
            _ => None,
        }
    }
}

/// Backwards-compat alias. Earlier code referred to this as `Command`;
/// the rename to `Directive` reflects that it's the wire-format token,
/// not a parser-internal dispatch label.
pub(crate) type Command = Directive;

pub(crate) fn parse_error(
    paops: &ParseOps,
    lineno: i32,
    line: &str,
    msg: impl Into<String>,
) -> Error {
    Error::Parse {
        file: paops.runtime.fname.clone(),
        lineno,
        msg: msg.into() + "\n" + line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::BufReader;
    use tempfile::tempdir;

    fn parse_ept(ept_file: &str) -> (TextTree, ParseOps, tempfile::TempDir) {
        let casdir = tempdir().unwrap();
        let mut paops = ParseOps {
            runtime: RuntimeState {
                fname: ept_file.to_string(),
                level: 0,
            },
            io: IoConfig {
                casdir: casdir.path().to_path_buf(),
                verbose: false,
                inline_data: false,
            },
            ..ParseOps::new(crate::crypto::default_policy()).unwrap()
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
    fn directive_round_trips_through_keyword() {
        // Every variant's keyword() must round-trip through from_keyword().
        // Catches typos and case mismatches early.
        for d in [
            Directive::Begin,
            Directive::End,
            Directive::Data,
            Directive::Stored,
            Directive::Encrypted,
            Directive::Chain,
            Directive::Conflict,
            Directive::Include,
        ] {
            let kw = d.keyword();
            assert_eq!(Directive::from_keyword(kw), Some(d));
        }
    }

    #[test]
    fn directive_keywords_are_uppercase() {
        // Wire-format stability: keywords are always uppercase ASCII.
        for d in [
            Directive::Begin,
            Directive::End,
            Directive::Data,
            Directive::Stored,
            Directive::Encrypted,
            Directive::Chain,
            Directive::Conflict,
            Directive::Include,
        ] {
            let kw = d.keyword();
            assert!(
                kw.chars().all(|c| c.is_ascii_uppercase()),
                "keyword '{}' must be uppercase ASCII",
                kw
            );
        }
    }

    #[test]
    fn empty_command_line_is_skipped() {
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        paops.runtime.fname = "<test>".into();
        let input = "// <( )>\n";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        assert!(tree.is_empty());
    }
}
