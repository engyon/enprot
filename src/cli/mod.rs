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

//! CLI dispatch layer — gated behind the `cli` feature. Contains
//! all clap-dependent types (CommonArgs, Command, *Subcmd structs)
//! and the `app_main` entry point. Library-only consumers build
//! with `--no-default-features` and get the crypto / parsing /
//! capability / ledger modules without pulling in clap.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::etree::ParseOps;
use crate::{Error, Result, capability, config, consts, output};

mod audit_cmd;
mod cap;
mod cas_cmd;
/// Per-subcommand modules. Each one exposes a `pub fn run(args)` entry
/// point that `app_main`'s match dispatches to.
mod chain_head_cmd;
mod color;
mod doctor;
mod init;
mod inspect;
mod list;
mod merge_cmd;
mod migrate_keys;
pub mod pipeline;
mod pki_cmd;
mod provenance_cmd;
mod rotate;
mod sbom_cmd;
mod smudge;
mod validate;
mod verify;
mod verify_chain;

/// CommonArgs → ParseOps resolution (architecture review round 2):
/// config merge, policy resolution, separator fallback, anchor
/// construction, the tree walk. Re-exported so sibling modules'
/// `super::{…}` imports continue to resolve.
pub(super) mod common;

// Phase-B relocations (arch review round 4): each subcommand's Args
// struct lives beside its handler; re-exported here so the enum +
// dispatch (which stay in this file) and any cross-module importer
// resolve unchanged.
pub(crate) use chain_head_cmd::{AuditLogSubcmd, PinSubcmd, SnapshotSubcmd};
use common::{apply_common, resolve_policy, with_config};
pub(crate) use init::InitSubcmd;
pub(crate) use inspect::InspectSubcmd;
pub(crate) use merge_cmd::{ConflictsSubcmd, MergeDriverSubcmd, ResolveSubcmd};
pub(crate) use migrate_keys::MigrateKeysSubcmd;
pub(crate) use pki_cmd::{FingerprintSubcmd, KeygenSubcmd, SignSubcmd, VerifySigSubcmd};
pub(crate) use provenance_cmd::{AttestSubcmd, ManifestSubcmd, ScmSubcmd};
pub(crate) use rotate::RotateSubcmd;
pub(crate) use smudge::SmudgeCleanSubcmd;
pub(crate) use verify_chain::VerifyChainSubcmd;

/// Top-level CLI. Every invocation picks one subcommand.
#[derive(Parser)]
#[command(
    name = "enprot",
    version,
    about = "Engyon Protected Text (EPT) confidentiality processor"
)]
pub struct Cli {
    /// Common arguments accepted in any position (before or after the
    /// subcommand name). Each field has `global = true` so clap recognises
    /// it at top-level or inside any subcommand.
    #[command(flatten)]
    pub common: CommonArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt WORD segments in the input file(s).
    Encrypt(EncryptSubcmd),
    /// Decrypt WORD segments in the input file(s).
    Decrypt(OperationSubcmd),
    /// Store (unencrypted) WORD segments to CAS.
    Store(OperationSubcmd),
    /// Fetch (unencrypted) WORD segments from CAS.
    Fetch(OperationSubcmd),
    /// Encrypt and store WORD segments (shorthand for `encrypt` plus store mode).
    EncryptStore(EncryptSubcmd),
    /// Parse and re-write each input without applying any transform.
    /// Useful for validating markup or measuring parse performance.
    Passthrough(OperationSubcmd),
    /// Verify file integrity: check markup structure, CAS pointers,
    /// and extfield format without decrypting.
    Verify(OperationSubcmd),
    /// List all WORD segments in the input file(s).
    List(OperationSubcmd),
    /// Print shell completion script to stdout.
    ///
    /// Install with: enprot completions bash > /etc/bash_completion.d/enprot
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Emit a Software Bill of Materials for this binary (Rust
    /// crates from the build-time Cargo.lock + the linked C
    /// libraries' runtime versions). SPDX 2.3 or CycloneDX 1.5 JSON.
    Sbom(sbom_cmd::SbomSubcmd),
    /// Generate a keypair (e.g. Ed25519) and write the PEM-encoded
    /// halves to `--out-priv` / `--out-pub`.
    Keygen(KeygenSubcmd),
    /// Sign FILE (or stdin) with `--key` and write a detached signature
    /// to `--out` (default: `<FILE>.sig`).
    Sign(SignSubcmd),
    /// Verify a detached signature (`SIG`, default `<FILE>.sig`)
    /// against FILE using `--key`. Named `verify-sig` to avoid clashing
    /// with the existing `verify` subcommand, which checks EPT markup.
    VerifySig(VerifySigSubcmd),
    /// Compute and print the SHA3-256 fingerprint of a PEM-encoded
    /// pubkey. Useful for building `trust_roots` lists in policy
    /// files (TODO.finalize/26) and for visually comparing two keys
    /// for equality.
    Fingerprint(FingerprintSubcmd),
    /// Walk the chain anchor DAG in FILE(s): check that every CHAIN
    /// block's signature validates against the named signer's pubkey,
    /// that parent references resolve to earlier anchors, and that
    /// There are no cycles. Exit non-zero on any failure (CI-friendly).
    VerifyChain(VerifyChainSubcmd),
    /// Re-sign CHAIN anchors in FILE(s) under a new key/algorithm —
    /// the post-quantum migration path (TODO.complete/58). Verifies
    /// every old signature before rewriting anything; parents and
    /// payload hashes are preserved, parent references are rewired
    /// to the re-signed anchors' new hashes.
    MigrateKeys(MigrateKeysSubcmd),
    /// Re-wrap escrow-mode blocks' key material under a new password
    /// and/or new recovery keys WITHOUT re-encrypting the payload.
    /// The payload ciphertext stays byte-identical (CAS pointers
    /// remain valid); only the CEK wraps change.
    Rotate(RotateSubcmd),
    /// Append-only signed audit log. Each line on stdin becomes a
    /// signed chain anchor in FILE — `tail -f` for cryptographic
    /// logs. Verify later with `enprot verify-chain --trust-root`.
    AuditLog(AuditLogSubcmd),
    /// Print the current chain head hash of FILE. The head is the
    /// AnchorHash of the last CHAIN block (or a full-file SHA3-256
    /// if the file has no anchors). Publish the hash out-of-band;
    /// later verify with `enprot pin`.
    Snapshot(SnapshotSubcmd),
    /// Verify that FILE's chain head hash matches EXPECTED-HASH.
    /// Exit non-zero on mismatch. Use after `enprot snapshot` to
    /// detect retroactive modification against a published pin.
    Pin(PinSubcmd),
    /// Print the capability set implied by the current flags (passwords,
    /// CAS dir, key files) and exit. No file transformation occurs.
    /// Useful for verifying "what would I be able to do?" before running
    /// a real command. Output is one capability per line.
    Capabilities,
    /// Query and verify the operational audit trail written via the
    /// global `--audit-log FILE` flag.
    Audit(audit_cmd::AuditArgs),
    /// Write a commented TOML template to `.enprot.toml` (or, with
    /// `--global`, to `~/.config/enprot/config.toml`). Refuses to
    /// overwrite an existing file. See TODO.roadmap/40.
    Init(InitSubcmd),
    /// Git merge-driver contract: `enprot merge-driver %O %A %B %P`
    /// (TODO.roadmap/43). Performs a three-way WORD-aware merge and
    /// writes the result back into `%A` (the "ours" path). Emits
    /// CONFLICT markers when both sides modified the same WORD region
    /// differently.
    MergeDriver(MergeDriverSubcmd),
    /// Walk CONFLICT blocks in FILE and replace each one with the
    /// chosen resolution (TODO.roadmap/44). The default mode is
    /// `--interactive`; pass `--ours`/`--theirs`/`--both`/`--skip`
    /// for non-interactive runs (e.g., CI).
    Resolve(ResolveSubcmd),
    /// Walk CONFLICT blocks in FILE and print one summary line per
    /// conflict (TODO.roadmap/49). Exit non-zero if any conflicts
    /// remain — CI-friendly as a gate after a merge-driver step.
    Conflicts(ConflictsSubcmd),
    /// Combined diagnostic: show structure + integrity + capabilities
    /// in one pass (TODO.finalize/42). Useful for debugging
    /// "what is this file and what can I do with it?".
    Inspect(InspectSubcmd),
    /// Diagnose the environment: versions, linked libraries,
    /// resolved policy, CAS writability, locale, git filter wiring.
    /// One command for bug reports, compliance attestation, and
    /// onboarding sanity checks. Exit 1 on any critical failure.
    Doctor,
    /// Capability policy queries: list declared WORDs, check access,
    /// explain decisions (TODO.complete/25).
    Cap(cap::CapArgs),
    /// Git `clean` filter (TODO.roadmap/45): read plaintext from
    /// stdin, write ciphertext to stdout. Used by `.gitattributes`
    /// `filter=enprot`. Defaults to `aes-256-gcm-siv-det` so the
    /// ciphertext is deterministic and diffs are stable.
    Clean(SmudgeCleanSubcmd),
    /// Git `smudge` filter: read ciphertext from stdin, write
    /// plaintext to stdout. Inverse of `clean`. Requires the WORD
    /// password (from `-k` or `ENPROPT_KEY`).
    Smudge(SmudgeCleanSubcmd),
    /// Git `textconv` for readable diffs (alias for `smudge`).
    Textconv(SmudgeCleanSubcmd),
    /// Build a provenance manifest for a directory (TODO.roadmap/51):
    /// walk the tree, store each file in CAS, emit INCLUDE per file.
    /// Output is an EPT file ready for `enprot attest`.
    Manifest(ManifestSubcmd),
    /// Append a signed chain anchor to a provenance manifest
    /// (TODO.roadmap/51). The anchor commits to the manifest's full
    /// state — any later tampering invalidates the signature.
    Attest(AttestSubcmd),
    /// Supply-chain manifest operations (TODO.roadmap/52). Wraps
    /// provenance with dependency parsing, structural diff, and a
    /// customer-side verify entry point. Subcommand form:
    /// `enprot scm {init,add,deps,attest,verify,diff}`.
    Scm(ScmSubcmd),
    /// CAS integrity operations (TODO.complete/67). Subcommand form:
    /// `enprot cas {verify}`. `cas verify` walks the input file(s),
    /// collects every STORED/INCLUDE/MUTED/KEY/CERT hash reference,
    /// and confirms each resolves to a CAS blob whose SHA3-256
    /// matches the declared hash.
    Cas(cas_cmd::CasArgs),
}

#[derive(Subcommand)]
pub enum ScmCommand {
    /// Create an empty manifest at MANIFEST.
    Init {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },
    /// Append PATH (file or directory) to MANIFEST.
    Add {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Parse Cargo.toml at MANIFEST_FILE and append each `[dependencies]`
    /// entry as an INCLUDE.
    Deps {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        #[arg(value_name = "Cargo.toml")]
        cargo_toml: PathBuf,
    },
    /// Sign MANIFEST with --signer (delegates to provenance::attest).
    Attest {
        #[arg(long, value_name = "PRIV.pem")]
        signer: PathBuf,
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },
    /// Verify MANIFEST with --trust-root (delegates to verify-chain).
    Verify {
        #[arg(long, value_name = "PUB.pem")]
        trust_root: PathBuf,
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },
    /// Structural diff between OLD and NEW manifests.
    Diff {
        #[arg(value_name = "OLD")]
        old: PathBuf,
        #[arg(value_name = "NEW")]
        new: PathBuf,
    },
}

/// Encrypt subcommand: encrypt-specific options plus the shared output
/// wiring.
#[derive(Args)]
pub struct EncryptSubcmd {
    #[command(flatten)]
    pub encrypt: EncryptOpts,

    #[command(flatten)]
    pub output: OutputArgs,

    /// Recipient pubkey (PEM). Repeatable. When supplied, the
    /// transform uses ML-KEM encapsulation instead of PBKDF
    /// (TODO.roadmap/60). Any one matching privkey can decrypt.
    #[arg(long = "recipient", value_name = "PUB.pem")]
    pub recipients: Vec<PathBuf>,
}

/// Decrypt/Store/Fetch/Passthrough subcommand: just the shared output
/// wiring (no crypto knobs).
#[derive(Args)]
pub struct OperationSubcmd {
    #[command(flatten)]
    pub output: OutputArgs,

    /// Private key (PEM) for KEM-mode decryption (TODO.roadmap/60).
    /// When the Encrypted block has a `recipients:` extfield, this
    /// privkey is used for ML-KEM decapsulation. Ignored for
    /// password-mode blocks.
    #[arg(long = "key-file", value_name = "PRIV.pem")]
    pub key_files: Vec<PathBuf>,
}

/// Crypto-policy, separators, RNG source, password store. Defined at
/// top-level with `global = true` on every field, so clap accepts these
/// flags before or after the subcommand name.
#[derive(Args, Clone, Debug)]
pub struct CommonArgs {
    /// Produce more verbose output.
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Suppress unnecessary output.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// Maximum recursion depth (0 = infinite).
    #[arg(long, global = true, default_value_t = consts::DEFAULT_MAX_DEPTH)]
    pub max_depth: usize,

    /// Specify left separator in parsing.
    #[arg(short = 'l', long, global = true, default_value = consts::DEFAULT_LEFT_SEP)]
    pub left_separator: String,

    /// Specify right separator in parsing.
    #[arg(short = 'r', long, global = true, default_value = consts::DEFAULT_RIGHT_SEP)]
    pub right_separator: String,

    /// Specify a secret PASSWORD for WORD (format: WORD=PASSWORD).
    ///
    /// One pair per occurrence; passwords containing commas are accepted
    /// verbatim. Use multiple `-k` flags for multiple pairs.
    #[arg(short = 'k', long = "key", global = true, value_name = "WORD=PASSWORD", value_parser = parse_word_password)]
    pub password: Vec<(String, String)>,

    /// Directory for CAS files (default "cas" if it exists, else ".").
    #[arg(short = 'c', long, global = true, value_name = "DIRECTORY", value_parser = parse_casdir)]
    pub casdir: Option<PathBuf>,

    /// Set the policy to restrict cryptographic algorithms.
    #[arg(long, global = true, value_parser = PossibleValuesParser::new(consts::VALID_POLICIES.to_vec()))]
    pub policy: Option<String>,

    /// Load settings from POLICY, but do not enforce the policy.
    #[arg(long, global = true, value_parser = PossibleValuesParser::new(consts::VALID_POLICIES.to_vec()))]
    pub defaults: Option<String>,

    /// Select and enforce the use of FIPS-compliant algorithms (implies --policy=nist).
    #[arg(long, global = true)]
    pub fips: bool,

    /// Preset left/right separators for the host language.
    /// Overrides the default (`// <(` … `)>`). Explicit `-l`/`-r` flags
    /// take precedence over `--lang`.
    #[arg(long, global = true, value_parser = PossibleValuesParser::new(consts::LANG_SEPARATORS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>()))]
    pub lang: Option<String>,

    /// Signer backend (TODO.complete/56). v1: only `software`. The
    /// flag exists so downstream code can be written against the
    /// enum, and CI can assert it round-trips; selecting anything
    /// other than `software` returns an actionable error today.
    #[arg(long, global = true, value_name = "BACKEND",
          value_parser = clap::builder::PossibleValuesParser::new(["software"]))]
    pub signer_backend: Option<String>,

    /// Disable the PBKDF cache mechanism. Affects both encrypt (key
    /// derivation) and decrypt (same derivation, repeated per file).
    #[arg(long = "pbkdf-disable-cache", global = true)]
    pub pbkdf_disable_cache: bool,

    /// After running the transform, append a CHAIN block to the
    /// output that signs the new file state. Requires `--signer`.
    /// The resulting anchor can be verified later with
    /// `enprot verify-chain --trust-root <pubkey>`.
    ///
    /// Mutually exclusive with `passthrough` (which by definition
    /// performs no transformation and thus has nothing to anchor).
    #[arg(long, global = true)]
    pub anchor: bool,

    /// Private key (PEM) used to sign chain anchors when `--anchor`
    /// is set. The corresponding pubkey is derived automatically;
    /// pass it to `verify-chain --trust-root` later.
    #[arg(long, global = true, value_name = "PRIV.pem")]
    pub signer: Option<PathBuf>,

    /// Output format for inspection subcommands (`capabilities`,
    /// `list`, `verify-chain`). `text` is the default; `json` emits a
    /// versioned envelope (`$schema: enprot/v1`) suitable for
    /// machine consumption.
    #[arg(long, global = true, value_enum, default_value_t = output::OutputFormat::Text)]
    pub format: output::OutputFormat,

    /// Emit inline `DATA` blocks on encrypt instead of the default
    /// CAS-referenced `STORED ct <hash>` (TODO.roadmap/42). Restores
    /// the pre-42 behavior; useful when CAS isn't available or for
    /// self-contained single-file output.
    #[arg(long, global = true)]
    pub inline: bool,

    /// Path to a capability policy TOML file (TODO.roadmap/46). When
    /// set, `verify-chain` checks trust roots and timestamp
    /// monotonicity, and `encrypt` refuses to write blocks for a WORD
    /// whose required capability the caller doesn't hold.
    #[arg(long, global = true, value_name = "PATH")]
    pub policy_file: Option<PathBuf>,

    /// Export spans and metrics to an OTLP/HTTP collector at
    /// ENDPOINT (e.g. http://localhost:4318). Requires a build with
    /// the `telemetry` feature; the flag errors with a rebuild hint
    /// otherwise. See docs/observability for the metric catalog.
    #[arg(long, global = true, value_name = "URL")]
    pub otel_endpoint: Option<String>,

    /// Service name reported to the OTLP collector.
    #[arg(long, global = true, value_name = "NAME", default_value = "enprot")]
    pub otel_service_name: String,

    /// Trace sampling rate (0.0–1.0; 1.0 exports everything).
    #[arg(long, global = true, value_name = "RATE", default_value_t = 1.0)]
    pub otel_sample_rate: f64,

    /// Extra headers for the OTLP collector (e.g. api keys), as
    /// comma-separated k=v pairs.
    #[arg(long, global = true, value_name = "K=V,...", value_parser = parse_otel_headers_flag)]
    pub otel_headers: Option<std::collections::HashMap<String, String>>,

    /// Number of parallel threads for multi-file processing (default 1).
    /// When > 1, each file is processed in its own thread with an
    /// independent ParseOps instance — no shared mutable state.
    #[arg(long, global = true, default_value_t = 1)]
    pub jobs: usize,

    /// Parse and transform without writing output files (TODO.complete/69).
    /// Prints what would change to stderr. No CAS writes. Useful for
    /// previewing the effect of an operation before committing.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Append one operational audit record per invocation to this
    /// JSON Lines file (TODO.complete/63). The log is append-only;
    /// with `--signer` also set, each record is followed by an
    /// Ed25519 signature over its exact bytes. Query with `enprot
    /// audit query`, check integrity with `enprot audit verify`.
    #[arg(long, global = true, value_name = "FILE")]
    pub audit_log: Option<PathBuf>,

    /// Streaming transform+write (TODO.complete/35): plain text
    /// between blocks is written as it is read; each block is
    /// buffered, transformed, and written individually. Memory is
    /// bounded by the largest block instead of the file size; output
    /// is byte-identical to the default path on success. On a
    /// mid-file failure the output may be partially written (the
    /// default path leaves it empty). Ignored with --anchor (needs
    /// the full tree) and --dry-run.
    #[arg(long, global = true)]
    pub streaming: bool,
}
impl CommonArgs {
    /// Construct a CommonArgs with only the filter-context fields
    /// populated. Used by subcommands that don't take the full CLI
    /// surface (e.g., `scm verify`, which delegates to
    /// `verify_chain_files`). Producing this in one place keeps the
    /// filter-dispatch paths DRY: any new CommonArgs field added
    /// downstream doesn't need to be wired through every call site.
    pub fn for_filter(casdir: Option<PathBuf>) -> Self {
        CommonArgs {
            verbose: false,
            quiet: false,
            max_depth: consts::DEFAULT_MAX_DEPTH,
            signer_backend: None,
            left_separator: consts::DEFAULT_LEFT_SEP.to_string(),
            right_separator: consts::DEFAULT_RIGHT_SEP.to_string(),
            password: Vec::new(),
            casdir,
            policy: None,
            defaults: None,
            fips: false,
            lang: None,
            pbkdf_disable_cache: false,
            anchor: false,
            signer: None,
            format: output::OutputFormat::Text,
            inline: false,
            policy_file: None,
            otel_endpoint: None,
            otel_service_name: "enprot".into(),
            otel_sample_rate: 1.0,
            otel_headers: None,
            jobs: 1,
            dry_run: false,
            audit_log: None,
            streaming: false,
        }
    }
}

/// Encrypt-specific cryptographic knobs.
#[derive(Args, Default, Clone, Debug)]
pub struct EncryptOpts {
    /// Set the PBKDF algorithm to use when encrypting.
    #[arg(long, value_parser = PossibleValuesParser::new(consts::VALID_PBKDF_ALGS.to_vec()))]
    pub pbkdf: Option<String>,

    /// Set the millisecond count for the PBKDF algorithm.
    #[arg(long, value_name = "MSEC", value_parser = parse_positive_u32)]
    pub pbkdf_msec: Option<u32>,

    /// Set the salt length for the PBKDF.
    #[arg(long, value_name = "BYTES", value_parser = parse_positive_usize)]
    pub pbkdf_salt_len: Option<usize>,

    /// Advanced option for testing, do not use.
    #[arg(long, value_name = "PARAMS", hide = true)]
    pub pbkdf_params: Option<String>,

    /// Advanced option for testing, do not use.
    #[arg(long, value_name = "HEX", hide = true)]
    pub pbkdf_salt: Option<String>,

    /// Set the cipher algorithm to use when encrypting.
    #[arg(long, value_parser = PossibleValuesParser::new(consts::VALID_CIPHER_ALGS.to_vec()))]
    pub cipher: Option<String>,

    /// Advanced option for testing, do not use.
    #[arg(long, value_name = "ALG", hide = true)]
    pub cipher_iv: Option<String>,

    /// Compress plaintext with zlib deflate before encryption.
    /// Reduces ciphertext size for text-heavy inputs. The `compress:zlib`
    /// extfield is recorded so decrypt knows to decompress.
    #[arg(long)]
    pub compress: bool,

    /// Recovery pubkey (PEM) for escrow-mode encryption
    /// (TODO.complete/59). The payload key is additionally wrapped to
    /// this key; decrypt then works with the password OR any recovery
    /// privkey (`decrypt --key-file`). Repeatable.
    #[arg(long = "recovery-key", value_name = "PUB.pem")]
    pub recovery_key: Vec<PathBuf>,

    /// OpenPGP armored public key to receive the CEK alongside the
    /// password (SOPS-style recipients, via librnp). Decrypt with
    /// `--key-file secret.asc`. Repeatable.
    #[arg(long = "pgp-pubkey", value_name = "PUB.asc")]
    pub pgp_pubkey: Vec<PathBuf>,
}

/// Input/output wiring: which WORDs to operate on, which files to read,
/// where to write results.
#[derive(Args, Clone, Debug)]
pub struct OutputArgs {
    /// WORD segment to operate on. Repeatable; also accepts a
    /// comma-separated list (`-w Agent_007,GEHEIM`).
    #[arg(short = 'w', long = "word", value_name = "WORD", value_delimiter = ',')]
    pub word: Vec<String>,

    /// Specify output file for previous input.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Vec<String>,

    /// Use PREFIX for output filenames. If PREFIX ends with `/` or is an
    /// existing directory, each output is placed inside it with its
    /// original basename (issue #18). Otherwise PREFIX is prepended to
    /// each input path verbatim (the legacy behavior).
    #[arg(
        short = 'p',
        long = "prefix",
        default_value = "",
        allow_hyphen_values = true
    )]
    pub prefix: String,

    /// Directory to write outputs into. Shorthand for `--prefix DIR/`.
    /// Conflicts with `--prefix`.
    #[arg(long, value_name = "DIR", value_parser = parse_output_dir, conflicts_with = "prefix")]
    pub output_dir: Option<PathBuf>,

    /// Input file(s). "-" means stdin; default "-" if omitted.
    #[arg(value_name = "FILE", default_value = "-")]
    pub files: Vec<String>,
}

/// Load multiple PEM files into a Vec<String>. Used for --recipient
/// (pubkey) and --key-file (privkey) flags. (TODO.roadmap/60.)
fn load_pems(paths: &[PathBuf]) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|p| fs::read_to_string(p).map_err(Error::from))
        .collect()
}

fn load_privkey_pems(paths: &[PathBuf]) -> Result<Vec<String>> {
    load_pems(paths)
}

fn load_armors(paths: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let text = fs::read_to_string(p).map_err(Error::from)?;
        if !crate::openpgp::is_armored(&text) {
            return Err(Error::InvalidArg {
                arg: "--pgp-pubkey",
                reason: format!("{} is not an ASCII-armored OpenPGP key block", p.display()),
            });
        }
        out.push(text);
    }
    Ok(out)
}

fn parse_word_password(s: &str) -> std::result::Result<(String, String), String> {
    let (word, pass) = s
        .split_once('=')
        .ok_or_else(|| format!("Must be of the form WORD=PASSWORD, got '{}'", s))?;
    if word.is_empty() || pass.is_empty() {
        return Err(format!("Must be of the form WORD=PASSWORD, got '{}'", s));
    }
    Ok((word.to_string(), pass.to_string()))
}

fn parse_casdir(s: &str) -> std::result::Result<PathBuf, String> {
    // URI-shaped CAS specs (memory:, s3://bucket/prefix, …) are
    // backend selectors for open_cas, not filesystem paths; carry
    // them through for dispatch there.
    if s == "memory:" || s == "memory" || s.contains("://") || s == "rekor:" {
        return Ok(PathBuf::from(s));
    }
    let p = PathBuf::from(s);
    if p.is_dir() {
        Ok(p)
    } else {
        Err(format!("'{}' is not a directory", s))
    }
}

/// Value parser for `--output-dir`. The directory must already exist —
/// enprot doesn't create output trees for the user (yet). Use `-p` for
/// the prepend-string behavior if you want a non-existent prefix.
fn parse_output_dir(s: &str) -> std::result::Result<PathBuf, String> {
    let p = PathBuf::from(s);
    if p.is_dir() {
        Ok(p)
    } else {
        Err(format!("--output-dir '{}' is not a directory", s))
    }
}

fn parse_positive_u32(s: &str) -> std::result::Result<u32, String> {
    let n: u32 = s
        .parse()
        .map_err(|_| format!("expected a number > 0, got '{}'", s))?;
    if n == 0 {
        return Err(format!("expected a number > 0, got '{}'", s));
    }
    Ok(n)
}

fn parse_positive_usize(s: &str) -> std::result::Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("expected a number > 0, got '{}'", s))?;
    if n == 0 {
        return Err(format!("expected a number > 0, got '{}'", s));
    }
    Ok(n)
}

fn parse_otel_headers_flag(
    s: &str,
) -> std::result::Result<std::collections::HashMap<String, String>, String> {
    crate::telemetry::parse_otel_headers(s).map_err(|e| e.to_string())
}

pub fn app_main<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    // Install the tracing subscriber AFTER parsing so the --otel-*
    // flags govern export; without an endpoint this is exactly the
    // old fmt-to-stderr subscriber (ENPROT_LOG, default `warn`).
    // The guard flushes the OTLP exporters on drop — when app_main
    // returns.
    let otel_cfg = cli
        .common
        .otel_endpoint
        .as_ref()
        .map(|endpoint| {
            crate::telemetry::OtelConfig::new(
                endpoint.clone(),
                cli.common.otel_service_name.clone(),
                cli.common.otel_sample_rate,
                cli.common.otel_headers.clone().unwrap_or_default(),
            )
        })
        .transpose()?;
    let _otel_guard = crate::telemetry::init(otel_cfg.as_ref())?;

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "enprot starting");
    // Single dispatch site. Bypass arms (subcommands that don't need
    // config layering) call their handler directly. Config-needing
    // arms wrap their handler in `with_config`, which loads the
    // layered TOML config and merges it into `common` before invoking
    // the closure. Adding a new variant is a single new match arm —
    // the compiler enforces exhaustiveness, no `unreachable!` arms.
    let (audit_op, audit_words, audit_files) = audit_cmd::invocation_context(&cli.command);
    let audit_started = std::time::Instant::now();
    // The dispatch below consumes `cli.command` and moves `cli.common`
    // into some arms — snapshot the audit-relevant fields first.
    let audit_cfg = (cli.common.audit_log.clone(), cli.common.signer.clone());
    let result = match cli.command {
        // Bypass config layering.
        Command::Init(a) => init::run(a),
        Command::MergeDriver(a) => merge_cmd::run_merge_driver(a),
        Command::Resolve(a) => merge_cmd::run_resolve(a),
        Command::Conflicts(a) => merge_cmd::run_conflicts(a),
        Command::Inspect(a) => inspect::run(a, cli.common),
        Command::Doctor => with_config(cli.common, |common| doctor::run(&common, common.format)),
        Command::Cap(args) => cap::run(args, &cli.common),
        Command::Cas(args) => cas_cmd::run(args, &cli.common),
        Command::Clean(a) => smudge::run(smudge::Mode::Clean, a, cli.common),
        Command::Smudge(a) => smudge::run(smudge::Mode::Smudge, a, cli.common),
        Command::Textconv(a) => smudge::run(smudge::Mode::Smudge, a, cli.common),
        Command::Manifest(a) => provenance_cmd::run_manifest(a),
        Command::Attest(a) => provenance_cmd::run_attest(a),
        Command::Scm(a) => provenance_cmd::run_scm(a),
        // Config-needing: load config then dispatch.
        Command::Encrypt(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                recovery_pubs: load_pems(&a.encrypt.recovery_key)?,
                pgp_pubs: load_armors(&a.encrypt.pgp_pubkey)?,
                op: Some((a.encrypt, Operation::Encrypt)),
                recipient_pubs: load_pems(&a.recipients)?,
                recipient_privs: Vec::new(),
            })
        }),
        Command::Decrypt(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                op: Some((EncryptOpts::default(), Operation::Decrypt)),
                recipient_pubs: Vec::new(),
                recipient_privs: load_privkey_pems(&a.key_files)?,
                recovery_pubs: Vec::new(),
                pgp_pubs: Vec::new(),
            })
        }),
        Command::Store(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                op: Some((EncryptOpts::default(), Operation::Store)),
                recipient_pubs: Vec::new(),
                recipient_privs: Vec::new(),
                recovery_pubs: Vec::new(),
                pgp_pubs: Vec::new(),
            })
        }),
        Command::Fetch(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                op: Some((EncryptOpts::default(), Operation::Fetch)),
                recipient_pubs: Vec::new(),
                recipient_privs: Vec::new(),
                recovery_pubs: Vec::new(),
                pgp_pubs: Vec::new(),
            })
        }),
        Command::EncryptStore(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                recovery_pubs: load_pems(&a.encrypt.recovery_key)?,
                pgp_pubs: load_armors(&a.encrypt.pgp_pubkey)?,
                op: Some((a.encrypt, Operation::EncryptStore)),
                recipient_pubs: load_pems(&a.recipients)?,
                recipient_privs: Vec::new(),
            })
        }),
        Command::Passthrough(a) => with_config(cli.common, |common| {
            pipeline::run(pipeline::RunConfig {
                common,
                output: a.output,
                op: None,
                recipient_pubs: Vec::new(),
                recipient_privs: Vec::new(),
                recovery_pubs: Vec::new(),
                pgp_pubs: Vec::new(),
            })
        }),
        Command::Verify(a) => with_config(cli.common, |common| verify::run(common, a.output)),
        Command::List(a) => with_config(cli.common, |common| list::run(common, a.output)),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "enprot", &mut std::io::stdout());
            Ok(())
        }
        Command::Sbom(a) => sbom_cmd::run(a),
        Command::Keygen(a) => with_config(cli.common, |common| pki_cmd::keygen(common, a)),
        Command::Sign(a) => with_config(cli.common, |common| pki_cmd::sign(common, a)),
        Command::VerifySig(a) => with_config(cli.common, |common| pki_cmd::verify_sig(common, a)),
        Command::Fingerprint(a) => pki_cmd::fingerprint(a),
        Command::VerifyChain(a) => with_config(cli.common, |common| verify_chain::run(common, a)),
        Command::MigrateKeys(a) => with_config(cli.common, |common| migrate_keys::run(common, a)),
        Command::Rotate(a) => with_config(cli.common, |common| rotate::run(common, a)),
        Command::AuditLog(a) => with_config(cli.common, |common| {
            chain_head_cmd::audit_log_stream(common, a)
        }),
        Command::Snapshot(a) => chain_head_cmd::snapshot(a),
        Command::Pin(a) => chain_head_cmd::pin(a),
        Command::Audit(a) => audit_cmd::run(a),
        Command::Capabilities => with_config(cli.common, |common| {
            let policy = resolve_policy(&common)?;
            let mut paops = ParseOps::new(policy)?;
            apply_common(&common, &mut paops);
            let caps = capability::CapabilitySet::from_paops(&paops);
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            match common.format {
                output::OutputFormat::Text => {
                    for c in caps.iter_sorted() {
                        writeln!(out, "{}", c)?;
                    }
                }
                output::OutputFormat::Json => {
                    let dtos = caps
                        .iter_sorted()
                        .into_iter()
                        .map(capability_to_dto)
                        .collect::<Vec<_>>();
                    let payload = output::CapabilitiesOutput { capabilities: dtos };
                    writeln!(out, "{}", output::to_json(&payload)?)?;
                }
            }
            Ok(())
        }),
    };
    audit_cmd::maybe_record(
        audit_cfg.0.as_deref(),
        audit_cfg.1.as_deref(),
        &audit_op,
        &audit_words,
        &audit_files,
        audit_started,
        &result,
    );
    result
}

/// `enprot init` implementation: write the commented template either
/// to `.enprot.toml` in cwd or, with `--global`, to
/// `~/.config/enprot/config.toml`. Refuses to overwrite unless `--force`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Encrypt,
    Decrypt,
    Store,
    Fetch,
    EncryptStore,
}

impl Operation {
    /// Human-readable label for chain-anchor `mut:` field.
    fn label(self) -> &'static str {
        match self {
            Operation::Encrypt => "encrypt",
            Operation::Decrypt => "decrypt",
            Operation::Store => "store",
            Operation::Fetch => "fetch",
            Operation::EncryptStore => "encrypt-store",
        }
    }
}

/// Translate a [`capability::Capability`] into a stable DTO for JSON output.
fn capability_to_dto(c: &capability::Capability) -> output::CapabilityDto {
    use capability::Capability::*;
    match c {
        Viewer => output::CapabilityDto {
            tier: "viewer",
            word: None,
            key_fp: None,
        },
        Reader => output::CapabilityDto {
            tier: "reader",
            word: None,
            key_fp: None,
        },
        Decryptor(w) => output::CapabilityDto {
            tier: "decryptor",
            word: Some(w.to_string()),
            key_fp: None,
        },
        Signer(fp) => output::CapabilityDto {
            tier: "signer",
            word: None,
            key_fp: Some(fp.to_hex()),
        },
        Verifier(fp) => output::CapabilityDto {
            tier: "verifier",
            word: None,
            key_fp: Some(fp.to_hex()),
        },
    }
}
