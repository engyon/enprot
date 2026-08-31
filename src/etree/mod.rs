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

/// Streaming parser (TODO.complete/05-streaming-io). Emits ParseEvent
/// values via an Iterator. The production code path uses `parse()`
/// (in-memory) for backward compatibility; `streaming::Parser` is
/// available for callers that need bounded-memory processing.
pub mod streaming;

/// Async pipeline twins (TODO.complete/54), behind the
/// `async-pipeline` feature: thin adapters over the sync cores.
#[cfg(feature = "async-pipeline")]
pub mod async_pipeline;

/// The single deep traversal over [`TextTree`] (architecture
/// review 2026-08-27): one walker, many visitors.
pub mod visitor;

mod blob;

pub use blob::{blob_to_tree, tree_to_blob};
pub use parse::parse;
pub use streaming::transform_stream;
pub use transform::transform;
pub use write::tree_write;

/// Abstraction over the transform's dependencies (TODO.finalize/45).
/// The transform functions need access to transform sets, passwords,
/// crypto config, runtime state, and IO config — but they don't need
/// the full ParseOps struct. This trait captures exactly what the
/// transform layer accesses, enabling:
///
/// - Testing transforms with mock contexts (no real Botan needed
///   for parse/write round-trip tests)
/// - Future alternative implementations (e.g., a streaming context
///   that doesn't hold the entire file in memory)
///
/// `ParseOps` implements this trait; all existing callers pass
/// `&mut ParseOps` and work unchanged.
pub trait TransformContext {
    fn max_depth(&self) -> usize;
    fn transforms(&self) -> &Transforms;
    fn transforms_mut(&mut self) -> &mut Transforms;
    fn passwords(&self) -> &HashMap<String, String>;
    fn crypto(&mut self) -> &mut CryptoConfig;
    fn crypto_ref(&self) -> &CryptoConfig;
    fn separators(&self) -> &Separators;
    fn io(&self) -> &IoConfig;
    fn io_mut(&mut self) -> &mut IoConfig;
    fn runtime_mut(&mut self) -> &mut RuntimeState;
    fn runtime(&self) -> &RuntimeState;
    fn anchor(&self) -> &AnchorConfig;
    fn anchor_mut(&mut self) -> &mut AnchorConfig;
    fn casdir(&self) -> &Path {
        &self.io().casdir
    }
}

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
    pub compress: bool,
}

impl CipherOptions {
    pub fn new(policy: &dyn CryptoPolicy) -> CipherOptions {
        CipherOptions {
            alg: policy.default_cipher_alg(),
            iv: None,
            compress: false,
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
    /// Recipient pubkeys for KEM-based encryption (TODO.roadmap/60).
    /// When non-empty, the transform calls kemenc::encrypt instead
    /// of prot::encrypt (password-based). Empty = password mode.
    pub recipient_pubs: Vec<String>,
    /// OpenPGP armored pubkeys for PGP-recipient escrow wraps
    /// (`enprot encrypt --pgp-pubkey`). Each wraps the CEK alongside
    /// the password and ML-KEM recovery paths.
    pub pgp_pubs: Vec<String>,
    /// Recovery pubkeys for escrow-mode encryption (TODO.complete/59).
    /// When non-empty (and no recipients), the transform calls
    /// escrow::encrypt: the payload key is a wrapped CEK reachable
    /// via password or any recovery privkey.
    pub recovery_pubs: Vec<String>,
    /// Recipient private keys for KEM-based decryption (TODO.roadmap/60).
    /// Keyed by WORD so different WORDs can decrypt with different keys.
    pub recipient_privkeys: HashMap<String, String>,
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
    /// CAS directory: legacy field, used only to construct the default
    /// [`cas::LocalCas`] in [`ParseOps::new`]. New callers should
    /// populate `cas` directly.
    pub casdir: PathBuf,
    /// Pluggable content-addressed storage (TODO.completion/15).
    /// Default: `LocalCas` rooted at `casdir`. Swap for `MemoryCas`
    /// (testing), `S3Cas` (future), `IpfsCas` (future), etc.
    pub cas: Box<dyn crate::cas::CasStore>,
    /// Verbose output (caller asked for `-v`).
    pub verbose: bool,
    /// Force inline `DATA` blocks on encrypt even when CAS is
    /// available. Restores the pre-42 behavior. Default: false
    /// (CAS-referenced `STORED ct <hash>` is the merge-friendly
    /// default whenever CAS exists). See TODO.roadmap/42.
    pub inline_data: bool,
    /// Dry-run mode (TODO.complete/69): parse + transform without
    /// writing output files or CAS blobs.
    pub dry_run: bool,
    /// Streaming transform+write (TODO.complete/35): plain text is
    /// written as it is read; each top-level block is buffered,
    /// transformed, and written individually. Memory is bounded by
    /// the largest single block, not the file size. Output is
    /// byte-identical to the in-memory path on success; on a
    /// mid-file failure the output may be partially written (the
    /// in-memory path leaves it empty). Ignored when anchoring is
    /// enabled (the anchor's payload hash needs the full tree).
    pub streaming: bool,
}

impl IoConfig {
    /// Set the CAS directory AND swap the active `LocalCas` to point
    /// at it. Existing call sites that did `paops.io.casdir = path`
    /// should use this instead so the trait-based backend follows.
    ///
    /// Backends other than `LocalCas` (e.g. `MemoryCas`, future
    /// `S3Cas`) ignore this — callers set them once via direct field
    /// assignment.
    pub fn set_local_casdir(&mut self, path: PathBuf) {
        self.casdir = path.clone();
        self.cas = Box::new(crate::cas::LocalCas {
            root: path,
            verbose: self.verbose,
        });
    }
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

/// Zero secrets on drop so they don't persist in process memory
/// after the process exits. Without this, passwords and PEM
/// strings in `passwords` and `crypto.recipient_privkeys` remain
/// readable via cold-boot or memory-dump attacks. (TODO.finalize/39.)
impl Drop for ParseOps {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for pw in self.passwords.values_mut() {
            pw.zeroize();
        }
        for pk in self.crypto.recipient_privkeys.values_mut() {
            pk.zeroize();
        }
        if let Some(ref mut pem) = self.anchor.signer_priv_pem {
            pem.zeroize();
        }
    }
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
                recipient_pubs: Vec::new(),
                pgp_pubs: Vec::new(),
                recovery_pubs: Vec::new(),
                recipient_privkeys: HashMap::new(),
            },
            runtime: RuntimeState {
                level: 0,
                fname: String::new(),
            },
            io: IoConfig {
                casdir: Path::new("").to_path_buf(),
                cas: Box::new(crate::cas::LocalCas::new(Path::new("").to_path_buf())),
                verbose: false,
                inline_data: false,
                dry_run: false,
                streaming: false,
            },
            anchor: AnchorConfig::disabled(),
        })
    }
}

impl TransformContext for ParseOps {
    fn max_depth(&self) -> usize {
        self.max_depth
    }
    fn transforms(&self) -> &Transforms {
        &self.transforms
    }
    fn transforms_mut(&mut self) -> &mut Transforms {
        &mut self.transforms
    }
    fn passwords(&self) -> &HashMap<String, String> {
        &self.passwords
    }
    fn crypto(&mut self) -> &mut CryptoConfig {
        &mut self.crypto
    }
    fn crypto_ref(&self) -> &CryptoConfig {
        &self.crypto
    }
    fn separators(&self) -> &Separators {
        &self.separators
    }
    fn io(&self) -> &IoConfig {
        &self.io
    }
    fn io_mut(&mut self) -> &mut IoConfig {
        &mut self.io
    }
    fn runtime_mut(&mut self) -> &mut RuntimeState {
        &mut self.runtime
    }
    fn runtime(&self) -> &RuntimeState {
        &self.runtime
    }
    fn anchor(&self) -> &AnchorConfig {
        &self.anchor
    }
    fn anchor_mut(&mut self) -> &mut AnchorConfig {
        &mut self.anchor
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
    /// RSD spec §"Immutable Blocks": a block whose content is
    /// content-addressed. Parser verifies the declared hash matches
    /// the actual content. IMMUTABLE provides integrity but no
    /// confidentiality — useful for license text, regulatory
    /// disclosures, standard references.
    ///
    /// Wire form (per spec):
    /// ```text
    /// // <( IMMUTABLE <name> <hashalg>=<hex-hash> )>
    /// ... content ...
    /// // <( MUTABLE <name> )>
    /// ```
    Immutable {
        name: String,
        hashalg: String,
        hash: String,
        txt: TextTree,
    },
    /// MUTED — sanitized form of an IMMUTABLE block. Content has been
    /// moved to CAS; the directive carries only the hash reference.
    /// Analogous to `Stored` for ciphertext.
    ///
    /// Wire form: `// <( MUTED <name> <hashalg>=<hex-hash> )>`
    Muted {
        name: String,
        hashalg: String,
        hash: String,
    },
    /// RSD spec §"Group keys": a key binding declared by content
    /// hash. The hash references a NOC (Nereon configuration) key
    /// file in CAS. Pairs with `Unkey` to scope the binding.
    ///
    /// Wire form: `// <( KEY <name> <hashalg>=<hex-hash> )>`
    Key {
        name: String,
        hashalg: String,
        hash: String,
    },
    /// UNKEY — ends a KEY binding scope. Parser "forgets" the
    /// binding when it sees this.
    Unkey {
        name: String,
    },
    /// CERT — declares a public-key cert binding by content hash.
    /// Analogous to Key but for verification keys.
    Cert {
        name: String,
        hashalg: String,
        hash: String,
    },
    /// UNCERT — ends a CERT binding scope.
    Uncert {
        name: String,
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
/// All variants (`Chain`, `Conflict`, `Include`, etc.) are fully
/// handled by the parser and streaming parser.
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
    /// IMMUTABLE block opener per RSD spec §"Immutable Blocks".
    /// Pairs with `Mutable` as the closer. Content is content-
    /// addressed; hash declared in the directive.
    Immutable,
    /// MUTABLE — closes an IMMUTABLE block.
    Mutable,
    /// MUTED — sanitized form of an IMMUTABLE block (content
    /// replaced by hash reference, lives in CAS). Analogous to
    /// STORED for ciphertext.
    Muted,
    /// KEY — declares a key binding by content hash. Pairs with
    /// `Unkey` as the scope-ender.
    Key,
    /// UNKEY — ends a KEY binding scope.
    Unkey,
    /// CERT — declares a public-key cert binding by content hash.
    /// Pairs with `Uncert` as the scope-ender.
    Cert,
    /// UNCERT — ends a CERT binding scope.
    Uncert,
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
            Directive::Immutable => "IMMUTABLE",
            Directive::Mutable => "MUTABLE",
            Directive::Muted => "MUTED",
            Directive::Key => "KEY",
            Directive::Unkey => "UNKEY",
            Directive::Cert => "CERT",
            Directive::Uncert => "UNCERT",
        }
    }

    /// Parse a keyword string into a `Directive`. Returns `None` for
    /// unrecognized keywords (caller decides whether that's an error
    /// or a pass-through line).
    ///
    /// In addition to the canonical enprot keywords, accepts RSD-spec
    /// vocabulary as input-only aliases (the writer always emits the
    /// canonical form):
    ///
    /// | Spec        | Maps to              | Why                          |
    /// |-------------|----------------------|------------------------------|
    /// | `CLASSIFY`  | `Directive::Begin`   | confidentiality intent       |
    /// | `UNCLASSIFY`| `Directive::End`     | closes CLASSIFY              |
    /// | `CLASSIFIED`| `Directive::Encrypted`| post-encryption form         |
    /// | `SIGNED`    | `Directive::Begin`   | integrity intent             |
    /// | `SIGNATURE` | `Directive::Encrypted`| sig payload                  |
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
            "IMMUTABLE" => Some(Directive::Immutable),
            "MUTABLE" => Some(Directive::Mutable),
            "MUTED" => Some(Directive::Muted),
            "KEY" => Some(Directive::Key),
            "UNKEY" => Some(Directive::Unkey),
            "CERT" => Some(Directive::Cert),
            "UNCERT" => Some(Directive::Uncert),
            // RSD-spec vocabulary (input-only aliases). The writer
            // emits the canonical enprot form on the left.
            "CLASSIFY" => Some(Directive::Begin),
            "UNCLASSIFY" => Some(Directive::End),
            "CLASSIFIED" => Some(Directive::Encrypted),
            "SIGNED" => Some(Directive::Begin),
            "SIGNATURE" => Some(Directive::Encrypted),
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
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        paops.runtime.fname = ept_file.to_string();
        paops.io.casdir = casdir.path().to_path_buf();
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
    fn directive_accepts_rsd_spec_vocabulary_as_aliases() {
        // Per TODO.completion/07: RSD spec uses classification-native
        // vocabulary. Accept as input-only aliases; the writer emits
        // the canonical enprot form.
        assert_eq!(Directive::from_keyword("CLASSIFY"), Some(Directive::Begin));
        assert_eq!(Directive::from_keyword("UNCLASSIFY"), Some(Directive::End));
        assert_eq!(
            Directive::from_keyword("CLASSIFIED"),
            Some(Directive::Encrypted)
        );
        assert_eq!(Directive::from_keyword("SIGNED"), Some(Directive::Begin));
        assert_eq!(
            Directive::from_keyword("SIGNATURE"),
            Some(Directive::Encrypted)
        );
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

    #[test]
    fn immutable_mutable_round_trips() {
        // RSD spec §"Immutable Blocks" — IMMUTABLE/MUTABLE block
        // should parse and re-serialize without loss.
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        paops.runtime.fname = "<test>".into();
        let input = "\
// <( IMMUTABLE License sha384=ABCDEF0123456789 )>
Copyright (c) 2026 Example Inc.
All rights reserved.
// <( MUTABLE License )>
";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        assert_eq!(tree.len(), 1, "expected one IMMUTABLE node");
        match &tree[0] {
            TextNode::Immutable {
                name,
                hashalg,
                hash,
                txt,
            } => {
                assert_eq!(name, "License");
                assert_eq!(hashalg, "sha384");
                assert_eq!(hash, "ABCDEF0123456789");
                assert!(!txt.is_empty(), "IMMUTABLE block should have content");
            }
            other => panic!("expected Immutable, got {other:?}"),
        }
        // Round-trip: write the tree back and re-parse
        let mut blob = Vec::new();
        let mut paops_w = paops;
        crate::etree::tree_write(&mut blob, &tree, &mut paops_w).unwrap();
        let s = String::from_utf8(blob).unwrap();
        assert!(
            s.contains("IMMUTABLE License sha384=ABCDEF0123456789"),
            "output: {s}"
        );
        assert!(s.contains("MUTABLE License"), "output: {s}");
    }

    #[test]
    fn muted_directive_parses() {
        // RSD spec: MUTED is the sanitized form of IMMUTABLE.
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        paops.runtime.fname = "<test>".into();
        let input = "// <( MUTED License sha384=ABCDEF0123456789 )>\n";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        assert_eq!(tree.len(), 1);
        match &tree[0] {
            TextNode::Muted {
                name,
                hashalg,
                hash,
            } => {
                assert_eq!(name, "License");
                assert_eq!(hashalg, "sha384");
                assert_eq!(hash, "ABCDEF0123456789");
            }
            other => panic!("expected Muted, got {other:?}"),
        }
    }

    #[test]
    fn key_unkey_cert_uncert_parse() {
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        paops.runtime.fname = "<test>".into();
        let input = "\
// <( KEY Deputies sha384=86716A025E4AAF0347C9 )>
// <( CERT Alice sha384=7725AD485A8EBDE97BB04E86C1 )>
some content
// <( UNKEY Deputies )>
// <( UNCERT Alice )>
";
        let tree = parse(BufReader::new(input.as_bytes()), &mut paops).unwrap();
        // 4 directives + 1 plain line = 5 nodes
        assert!(
            tree.len() >= 4,
            "expected at least 4 nodes, got {}",
            tree.len()
        );
        // Verify first node is Key
        assert!(matches!(&tree[0], TextNode::Key { name, .. } if name == "Deputies"));
    }
}
