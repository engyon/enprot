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

//! Engyon Protected Text (EPT) confidentiality processor.
//!
//! Enprot parses text/source files whose host-language comments contain
//! `BEGIN`/`END`/`STORED`/`ENCRYPTED`/`DATA` directives and applies four
//! idempotent transformations on the named segments: store, fetch, encrypt,
//! decrypt. The pipeline is `parse` → `transform` → `tree_write`, run once
//! per input file.
//!
//! Most callers want [`app_main`], which is the CLI entry point. The
//! `crypto` and `utils` modules are re-exported for integration tests.

pub mod capability;
mod cas;
mod cipher;
mod consts;
pub mod crypto;
mod error;
pub mod etree;
pub mod ledger;
pub mod merkle;
mod password;
mod pbkdf;
pub mod pki;
mod policy;
pub mod prot;
pub mod utils;

pub use error::{Error, Result};

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::builder::PossibleValuesParser;
use clap::{Args, CommandFactory, Parser, Subcommand};

/// Chain-anchor production config (TODO.finalize/17). Populated by
/// `run()` when `--anchor --signer <priv>` are both supplied. Lives
/// on `ParseOps` so the per-file pipeline can append anchors as it
/// writes outputs.
#[derive(Clone, Debug, Default)]
pub struct AnchorConfig {
    /// True iff `--anchor` was supplied AND `--signer <priv>` resolves.
    pub enabled: bool,
    /// Human-readable label of the operation that produced this anchor
    /// (e.g., "encrypt", "store", "encrypt-store"). Informational;
    /// appears in the `mut:` field of the wire-format CHAIN block.
    pub operation: String,
    /// WORDs the operation targeted. Joined into the `mut:` field.
    pub words: Vec<String>,
    /// Loaded once at startup; the privkey PEM that signs each anchor.
    /// The pubkey is derived from this via Botan (`Privkey::pubkey()`).
    pub signer_priv_pem: Option<String>,
}

impl AnchorConfig {
    pub fn disabled() -> Self {
        AnchorConfig::default()
    }
}

use crate::etree::ParseOps;

fn make_policy(name: &str) -> Box<dyn crypto::CryptoPolicy> {
    // Invariant: callers route `name` through clap's `VALID_POLICIES`
    // value_parser, so only "default" or "nist" reach here. Returning
    // an `Err` would be incorrect — this function is infallible by
    // contract; an unknown name indicates a programming error in the
    // caller, not user input.
    match name {
        "default" => Box::new(crypto::CryptoPolicyDefault {}),
        "nist" => Box::new(crypto::CryptoPolicyNIST {}),
        other => panic!(
            "make_policy: unknown policy '{}' (callers must validate via VALID_POLICIES)",
            other
        ),
    }
}

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
}

/// Encrypt subcommand: encrypt-specific options plus the shared output
/// wiring.
#[derive(Args)]
pub struct EncryptSubcmd {
    #[command(flatten)]
    pub encrypt: EncryptOpts,

    #[command(flatten)]
    pub output: OutputArgs,
}

/// Decrypt/Store/Fetch/Passthrough subcommand: just the shared output
/// wiring (no crypto knobs).
#[derive(Args)]
pub struct OperationSubcmd {
    #[command(flatten)]
    pub output: OutputArgs,
}

/// `keygen` subcommand: emit a fresh keypair.
#[derive(Args)]
pub struct KeygenSubcmd {
    /// Signature algorithm.
    #[arg(value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Write private key to PATH (PEM). Default: stdout.
    #[arg(long = "out-priv", value_name = "PATH")]
    pub out_priv: Option<PathBuf>,

    /// Write public key to PATH (PEM). Default: stdout.
    #[arg(long = "out-pub", value_name = "PATH")]
    pub out_pub: Option<PathBuf>,
}

/// `sign` subcommand: produce a detached signature.
#[derive(Args)]
pub struct SignSubcmd {
    /// Signature algorithm (must match the key type).
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Private key (PEM) to sign with. Named `--key-file` because the
    /// global `-k/--key` already means a symmetric WORD=PASSWORD pair.
    #[arg(long = "key-file", value_name = "PRIV.pem")]
    pub key: PathBuf,

    /// Input file (omit to read stdin).
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Write signature to PATH. Default: `<FILE>.sig`, or stdout when
    /// reading from stdin.
    #[arg(short = 'o', long = "out", value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// `verify-sig` subcommand: verify a detached signature.
#[derive(Args)]
pub struct VerifySigSubcmd {
    /// Signature algorithm (must match the key type).
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(
        pki::SigAlgKind::ALL.iter().map(|k| k.name()).collect::<Vec<_>>()
    ))]
    pub alg: String,

    /// Public key (PEM) to verify against. See `sign --key-file` for
    /// the naming rationale.
    #[arg(long = "key-file", value_name = "PUB.pem")]
    pub key: PathBuf,

    /// Signature file. Default: `<FILE>.sig`. Required when reading
    /// the message from stdin.
    #[arg(long = "sig-file", value_name = "SIG")]
    pub sig: Option<PathBuf>,

    /// Input file (omit to read stdin).
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,
}

/// `fingerprint` subcommand: print the SHA3-256 fingerprint of a
/// PEM-encoded pubkey. Used to populate `trust_roots` lists in
/// policy files (TODO.finalize/26) and to compare two keys for
/// equality without parsing the full PEM.
#[derive(Args)]
pub struct FingerprintSubcmd {
    /// Public key (PEM) to fingerprint.
    #[arg(value_name = "PUB.pem")]
    pub key: PathBuf,
}

/// `verify-chain` subcommand: walk a file's CHAIN anchors and verify
/// signatures + DAG structure. Repeatable `--trust-root` flags form
/// a whitelist; if non-empty, anchors signed by anything else fail.
#[derive(Args)]
pub struct VerifyChainSubcmd {
    /// Public key (PEM) whose fingerprint must match a CHAIN's
    /// `signer:` field. Repeatable; if non-empty, forms a trust
    /// whitelist. If empty, every anchor is checked against the
    /// pubkey whose fingerprint matches — and fails if no key
    /// matches.
    #[arg(long = "trust-root", value_name = "PUB.pem")]
    pub trust_roots: Vec<PathBuf>,

    /// Input file(s). Each is verified independently.
    #[arg(value_name = "FILE")]
    pub files: Vec<String>,
}

/// `audit-log` subcommand: stream lines from stdin into FILE as
/// signed chain anchors. Each line becomes one Plain node + one
/// CHAIN node appended to the file. Produces a linear, tamper-evident
/// log with O(1) verification per anchor.
#[derive(Args)]
pub struct AuditLogSubcmd {
    /// Private key (PEM) to sign each anchor. The pubkey is derived
    /// automatically; pass it to `verify-chain --trust-root` later.
    #[arg(long = "signer", value_name = "PRIV.pem")]
    pub signer: PathBuf,

    /// Log file. Appended to if it exists; created if not. Each
    /// invocation reads the existing content into memory, appends
    /// new anchors, and writes the result back atomically.
    #[arg(value_name = "FILE")]
    pub file: String,
}

/// `snapshot` subcommand: print the chain head hash.
#[derive(Args)]
pub struct SnapshotSubcmd {
    #[arg(value_name = "FILE")]
    pub file: String,
}

/// `pin` subcommand: verify the chain head hash matches EXPECTED.
#[derive(Args)]
pub struct PinSubcmd {
    /// Expected chain head hash (64 hex chars).
    #[arg(value_name = "EXPECTED-HASH")]
    pub expected: String,

    #[arg(value_name = "FILE")]
    pub file: String,
}

/// Crypto-policy, separators, RNG source, password store. Defined at
/// top-level with `global = true` on every field, so clap accepts these
/// flags before or after the subcommand name.
#[derive(Args)]
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
}

/// Encrypt-specific cryptographic knobs.
#[derive(Args, Default)]
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
}

/// Input/output wiring: which WORDs to operate on, which files to read,
/// where to write results.
#[derive(Args)]
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

pub fn app_main<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // <( ENCRYPTED AUTHOR )>
    // <( DATA X417HVMRRAs6Z1xGo5yY4TxUQ2tpAHEKQ1sg9+kfku5uUikK3y2tODtsUiGqfRGW )>
    // <( DATA xUCGYFu02BCdqPM7uuX5UNvbfrLvKkj6gLYwg/cr42PJmr4o5xnw1qo= )>
    // <( END AUTHOR )>

    let cli = Cli::parse_from(args);
    let common = cli.common;
    match cli.command {
        Command::Encrypt(a) => run(common, a.output, Some((a.encrypt, Operation::Encrypt))),
        Command::Decrypt(a) => run(
            common,
            a.output,
            Some((EncryptOpts::default(), Operation::Decrypt)),
        ),
        Command::Store(a) => run(
            common,
            a.output,
            Some((EncryptOpts::default(), Operation::Store)),
        ),
        Command::Fetch(a) => run(
            common,
            a.output,
            Some((EncryptOpts::default(), Operation::Fetch)),
        ),
        Command::EncryptStore(a) => {
            run(common, a.output, Some((a.encrypt, Operation::EncryptStore)))
        }
        Command::Passthrough(a) => run(common, a.output, None),
        Command::Verify(a) => verify_files(common, a.output),
        Command::List(a) => list_files(common, a.output),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "enprot", &mut std::io::stdout());
            Ok(())
        }
        Command::Keygen(a) => pki_keygen(common, a),
        Command::Sign(a) => pki_sign(common, a),
        Command::VerifySig(a) => pki_verify_sig(common, a),
        Command::Fingerprint(a) => pki_fingerprint(a),
        Command::VerifyChain(a) => verify_chain_files(common, a),
        Command::AuditLog(a) => audit_log_stream(common, a),
        Command::Snapshot(a) => snapshot_file(a),
        Command::Pin(a) => pin_file(a),
        Command::Capabilities => {
            let policy = resolve_policy(&common)?;
            let mut paops = ParseOps::new(policy)?;
            apply_common(&common, &mut paops);
            let caps = capability::CapabilitySet::from_paops(&paops);
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            for c in caps.iter_sorted() {
                writeln!(out, "{}", c)?;
            }
            Ok(())
        }
    }
}

#[derive(Copy, Clone)]
enum Operation {
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

fn run(common: CommonArgs, output: OutputArgs, op: Option<(EncryptOpts, Operation)>) -> Result<()> {
    let explicit_policy = common.policy.clone();
    let mut policy_name = explicit_policy
        .clone()
        .unwrap_or_else(|| consts::DEFAULT_POLICY.to_string());

    let fips = common.fips
        || (cfg!(unix)
            && match fs::read_to_string("/proc/sys/crypto/fips_enabled") {
                Ok(s) => s.starts_with('1'),
                Err(_) => false,
            });
    if fips {
        if let Some(p) = explicit_policy.as_deref()
            && p != "nist"
        {
            return Err(Error::Msg(format!(
                "Policy setting of '{}' conflicts with --fips",
                p
            )));
        }
        policy_name = "nist".to_string();
    }

    let policy = make_policy(&policy_name);
    let mut paops = if let Some(defaults) = common.defaults.as_deref() {
        let mut p = ParseOps::new(make_policy(defaults))?;
        p.crypto.policy = policy;
        p
    } else {
        ParseOps::new(policy)?
    };

    if let Some(dir) = common.casdir.clone() {
        paops.io.casdir = dir;
    } else if Path::new("cas").is_dir() {
        paops.io.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.io.casdir = Path::new(".").to_path_buf();
    }

    paops.io.verbose = common.verbose && !common.quiet;
    paops.max_depth = common.max_depth;
    let (left, right) = resolve_separators(&common);
    paops.separators.left = left;
    paops.separators.right = right;
    paops.passwords.extend(common.password);
    if common.pbkdf_disable_cache {
        paops.crypto.pbkdf_cache = None;
    }

    // Apply the operation: populate the transform sets on paops. `op == None`
    // means Passthrough — leave the sets empty.
    if let Some((enc_opts, op_kind)) = op.as_ref() {
        for w in &output.word {
            match op_kind {
                Operation::Encrypt => {
                    paops.transforms.encrypt.insert(w.clone());
                }
                Operation::Decrypt => {
                    paops.transforms.decrypt.insert(w.clone());
                }
                Operation::Store => {
                    paops.transforms.store.insert(w.clone());
                }
                Operation::Fetch => {
                    paops.transforms.fetch.insert(w.clone());
                }
                Operation::EncryptStore => {
                    paops.transforms.encrypt.insert(w.clone());
                    paops.transforms.store.insert(w.clone());
                }
            }
        }

        // PBKDF + cipher options only meaningful for encrypt / encrypt-store.
        if matches!(op_kind, Operation::Encrypt | Operation::EncryptStore) {
            if let Some(alg) = enc_opts.pbkdf.as_deref() {
                paops.crypto.pbkdfopts.alg = alg.to_string();
            }
            if let Some(saltlen) = enc_opts.pbkdf_salt_len {
                paops.crypto.pbkdfopts.saltlen = saltlen;
            }
            if let Some(msec) = enc_opts.pbkdf_msec {
                paops.crypto.pbkdfopts.msec = Some(msec);
            }
            if let Some(raw) = enc_opts.pbkdf_params.as_deref() {
                paops.crypto.pbkdfopts.msec = None;
                let params: std::collections::BTreeMap<String, usize> = raw
                    .split(',')
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').unwrap_or(("", "0"));
                        (k.to_string(), v.parse().unwrap_or(0))
                    })
                    .collect();
                paops.crypto.pbkdfopts.params = Some(params);
            }
            if let Some(salt_hex) = enc_opts.pbkdf_salt.as_deref() {
                paops.crypto.pbkdfopts.salt = Some(hex::decode(salt_hex).map_err(Error::from)?);
            }
            if let Some(c) = enc_opts.cipher.as_deref() {
                paops.crypto.cipheropts.alg = c.to_string();
            }
            if let Some(iv_hex) = enc_opts.cipher_iv.as_deref() {
                paops.crypto.cipheropts.iv = Some(hex::decode(iv_hex).map_err(Error::from)?);
            }
        }
    }

    if paops.io.verbose {
        eprintln!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.separators.left,
            paops.separators.right,
            paops.io.casdir.display(),
        );
    }

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );

    // Populate the anchor context once. `passthrough` (op == None) is
    // excluded because it performs no transformation and therefore
    // has nothing meaningful to anchor.
    paops.anchor = build_anchor_config(
        common.anchor,
        common.signer.as_deref(),
        op.as_ref().map(|(_, k)| *k),
        &output.word,
    )?;

    for (path_in, path_out) in files {
        process_one_file(&path_in, &path_out, &mut paops)?;
    }
    Ok(())
}

/// Pair each input with its output, following the rules in
/// `TODO.issues/18-output-directory-mode.md`:
///
/// 1. `--output <FILE>` paired with this input → use it as-is.
/// 2. `--output-dir <DIR>` given → `DIR + "/" + basename(input)`.
/// 3. `--prefix <PREFIX>` where PREFIX ends in `/` or is an existing
///    directory → same as `--output-dir` behaviour.
/// 4. `--prefix <PREFIX>` (other) → PREFIX prepended to input verbatim
///    (the legacy flat-CLI behavior).
/// 5. Input is `-` (stdin) → output is `-` (stdout passthrough).
/// 6. Otherwise → output = input (in-place).
fn pair_inputs_to_outputs(
    inputs: &[String],
    outputs: &[String],
    prefix: &str,
    output_dir: Option<&Path>,
) -> Vec<(String, String)> {
    let mut result = Vec::with_capacity(inputs.len());
    let mut out_iter = outputs.iter();
    let prefix_is_dir = !prefix.is_empty() && (prefix.ends_with('/') || Path::new(prefix).is_dir());

    for input in inputs {
        if let Some(output) = out_iter.next() {
            result.push((input.clone(), output.clone()));
            continue;
        }
        let output = if input == "-" {
            "-".to_string()
        } else if let Some(dir) = output_dir {
            join_with_basename(dir, input)
        } else if prefix_is_dir {
            let dir_str = prefix.trim_end_matches('/');
            join_with_basename(Path::new(dir_str), input)
        } else if prefix.is_empty() {
            input.clone()
        } else {
            format!("{}{}", prefix, input)
        };
        result.push((input.clone(), output));
    }
    result
}

fn join_with_basename(dir: &Path, input: &str) -> String {
    let base = Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.to_string());
    dir.join(base).to_string_lossy().into_owned()
}

fn build_anchor_config(
    anchor_flag: bool,
    signer_path: Option<&Path>,
    op_kind: Option<Operation>,
    words: &[String],
) -> Result<AnchorConfig> {
    if !anchor_flag {
        return Ok(AnchorConfig::disabled());
    }
    let signer_path =
        signer_path.ok_or_else(|| Error::msg("--anchor requires --signer <PRIV.pem>"))?;
    let priv_pem = fs::read_to_string(signer_path)?;
    let op = op_kind
        .map(|k| k.label())
        .unwrap_or("passthrough")
        .to_string();
    Ok(AnchorConfig {
        enabled: true,
        operation: op,
        words: words.to_vec(),
        signer_priv_pem: Some(priv_pem),
    })
}

fn process_one_file(path_in: &str, path_out: &str, paops: &mut ParseOps) -> Result<()> {
    if paops.io.verbose {
        eprintln!("Reading {}", path_in);
    }

    let reader_in: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match File::open(path_in) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                return Err(Error::Msg(format!(
                    "Failed to open {} for reading: {}",
                    path_in, e
                )));
            }
        }
    };

    paops.runtime.fname = if path_in == "-" {
        "<stdin>".to_string()
    } else {
        path_in.to_string()
    };

    let tree_in = etree::parse(reader_in, paops)
        .map_err(|e| Error::Msg(format!("{} in {}, aborting.", e, path_in)))?;

    if paops.io.verbose {
        eprintln!("Transforming {}", path_in);
    }
    let mut tree_out = etree::transform(&tree_in, paops)
        .map_err(|e| Error::Msg(format!("{} in {}, aborting.", e, path_in)))?;

    // Optionally append a CHAIN block signing the new file state.
    // Must happen BEFORE tree_write so the anchor lands in the output.
    if paops.anchor.enabled {
        let chain_node = build_chain_anchor_node(&tree_out, paops)?;
        tree_out.push(chain_node);
    }

    if paops.io.verbose {
        eprintln!("Writing {}", path_out);
    }

    let mut writer_out: Box<dyn Write> = if path_out == "-" {
        Box::new(BufWriter::new(std::io::stdout()))
    } else {
        match File::create(path_out) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                return Err(Error::Msg(format!(
                    "Failed to open {} for writing: {}",
                    path_out, e
                )));
            }
        }
    };

    etree::tree_write(&mut writer_out, &tree_out, paops)
        .map_err(|e| Error::Msg(format!("Write to {} failed: {}", path_out, e)))?;
    Ok(())
}

/// Build a [`TextNode::Chain`] node that signs the post-transform
/// `tree_out` state. The payload hash commits to the file content
/// EXCLUDING any chain anchors — that way the anchor isn't
/// self-referential and the hash is stable across re-anchoring.
///
/// parents: hashes of every CHAIN block already present in tree_out,
/// in file order. This makes the new anchor a linear descendant of
/// the most-recent prior anchor (TODO.finalize/17 DAG semantics;
/// multiple-parents / merge anchors are a future extension).
fn build_chain_anchor_node(
    tree_out: &etree::TextTree,
    paops: &mut ParseOps,
) -> Result<etree::TextNode> {
    use crate::ledger::{Anchor, PayloadHash, SignerId};
    use crate::pki::SigAlgKind;
    use std::collections::BTreeMap;

    let priv_pem = paops
        .anchor
        .signer_priv_pem
        .clone()
        .ok_or_else(|| Error::msg("anchor config missing signer_priv_pem"))?;

    // Derive pubkey from privkey; compute fingerprint.
    let botan_priv = botan::Privkey::load_pem(&priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let fp = capability::KeyFp::from_pem(&pub_pem)?;

    // payload_hash: SHA3-256 over the ENTIRE post-transform tree
    // (including any prior CHAIN blocks). This gives end-to-end
    // tamper detection: changing any earlier content invalidates
    // every subsequent anchor's payload. The new anchor itself
    // isn't in `tree_out` yet, so there's no self-reference.
    let blob = etree::tree_to_blob(tree_out, paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    let payload_hex = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
    let mut payload_arr = [0u8; 32];
    payload_arr.copy_from_slice(&hex::decode(payload_hex)?);
    let payload_hash = PayloadHash(payload_arr);

    // parents: latest existing CHAIN anchor only (linear chain).
    let parents = latest_existing_anchors(tree_out, paops)?;

    // mutations: e.g., "encrypt+Agent_007,GEHEIM". URL-encoded space.
    let words_joined = paops.anchor.words.join(",");
    let mutations = if words_joined.is_empty() {
        paops.anchor.operation.clone()
    } else {
        format!("{}+{}", paops.anchor.operation, words_joined)
    };

    let signer = SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = Anchor::builder(signer, payload_hash)
        .with_parents(parents)
        .with_mutations(mutations)
        .build();
    let signed = anchor.sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)?;
    let extfields: BTreeMap<String, String> = signed.to_extfields();
    Ok(etree::TextNode::Chain { extfields })
}

/// Return at most one parent: the [`AnchorHash`] of the LAST
/// [`TextNode::Chain`] in document order, or `None` if the tree has
/// no anchors. Linear-chain semantic — new anchors build on the tip.
fn latest_existing_anchors(
    tree: &etree::TextTree,
    _paops: &ParseOps,
) -> Result<Vec<crate::ledger::AnchorHash>> {
    let mut all = Vec::new();
    walk_for_chains(tree, &mut all)?;
    Ok(all.pop().into_iter().collect())
}

fn walk_for_chains(tree: &etree::TextTree, out: &mut Vec<crate::ledger::AnchorHash>) -> Result<()> {
    for node in tree {
        match node {
            etree::TextNode::Chain { extfields } => {
                let signed = crate::ledger::SignedAnchor::from_extfields(extfields)?;
                if let Ok(h) = signed.id() {
                    out.push(h);
                }
            }
            etree::TextNode::BeginEnd { txt, .. } | etree::TextNode::Encrypted { txt, .. } => {
                walk_for_chains(txt, out)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parse each input and list all WORD segments to stdout. One line per
/// directive node, with keyword, type, and crypto metadata.
fn list_files(common: CommonArgs, output: OutputArgs) -> Result<()> {
    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );

    let stdout = std::io::stdout();
    for (path_in, _) in &files {
        let reader: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            Box::new(BufReader::new(File::open(path_in).map_err(|e| {
                Error::Msg(format!("Failed to open {}: {}", path_in, e))
            })?))
        };
        paops.runtime.fname = path_in.clone();

        let tree = etree::parse(reader, &mut paops)?;

        let mut out = stdout.lock();
        if files.len() > 1 {
            writeln!(out, "== {} ==", path_in)?;
        }
        list_tree(&tree, 0, &mut out)?;
    }
    Ok(())
}

fn list_tree<W: Write>(tree: &etree::TextTree, depth: usize, out: &mut W) -> Result<()> {
    let indent = "  ".repeat(depth);
    for node in tree {
        match node {
            etree::TextNode::BeginEnd { keyw, txt } => {
                writeln!(out, "{}BEGIN/END  {}", indent, keyw)?;
                list_tree(txt, depth + 1, out)?;
            }
            etree::TextNode::Encrypted {
                keyw, extfields, ..
            } => {
                let cipher = extfields
                    .get("cipher")
                    .map(|s| s.as_str())
                    .unwrap_or("aes-256-siv");
                let pbkdf = extfields
                    .get("pbkdf")
                    .map(|s| s.split('$').nth(1).unwrap_or("?"))
                    .unwrap_or("legacy");
                writeln!(
                    out,
                    "{}ENCRYPTED {}  cipher={}  pbkdf={}",
                    indent, keyw, cipher, pbkdf
                )?;
            }
            etree::TextNode::Stored { keyw, cas } => {
                writeln!(
                    out,
                    "{}STORED    {}  cas={}…",
                    indent,
                    keyw,
                    &cas[..cas.len().min(16)]
                )?;
            }
            etree::TextNode::Plain(_) | etree::TextNode::Data(_) => {}
            etree::TextNode::Chain { extfields } => {
                let signer = extfields.get("signer").map(|s| s.as_str()).unwrap_or("?");
                let payload = extfields.get("payload").map(|s| s.as_str()).unwrap_or("?");
                let short_payload = &payload[..payload.len().min(16)];
                writeln!(
                    out,
                    "{}CHAIN     signer={}  payload={}…",
                    indent, signer, short_payload
                )?;
            }
        }
    }
    Ok(())
}

/// Parse each input and check structural integrity: valid EPT markup,
/// resolvable CAS pointers (file exists + hash matches), well-formed
/// cipher/pbkdf extfields. Reports per-file status to stderr; returns
/// Err on the first problem.
fn verify_files(common: CommonArgs, output: OutputArgs) -> Result<()> {
    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );

    let mut issues = 0usize;
    for (path_in, _) in &files {
        if paops.io.verbose {
            eprintln!("Verifying {}", path_in);
        }

        let reader: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            Box::new(BufReader::new(File::open(path_in).map_err(|e| {
                Error::Msg(format!("Failed to open {}: {}", path_in, e))
            })?))
        };
        paops.runtime.fname = path_in.clone();

        let tree = match etree::parse(reader, &mut paops) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL {}: parse error: {}", path_in, e);
                issues += 1;
                continue;
            }
        };

        for node in &tree {
            let node_issues = verify_node(node, &mut paops);
            issues += node_issues;
        }

        if issues == 0 {
            eprintln!("OK   {}", path_in);
        }
    }

    if issues > 0 {
        return Err(Error::Msg(format!("{} issue(s) found", issues)));
    }
    Ok(())
}

fn verify_node(node: &etree::TextNode, paops: &mut ParseOps) -> usize {
    match node {
        etree::TextNode::Stored { keyw, cas } => match cas::load(cas, paops) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("FAIL: CAS pointer '{}' for WORD '{}': {}", cas, keyw, e);
                1
            }
        },
        etree::TextNode::Encrypted { txt, extfields, .. } => {
            let mut n = 0;
            // Check inner node
            for child in txt {
                n += verify_node(child, paops);
            }
            // Validate extfield format
            if let Some(cipher_str) = extfields.get("cipher") {
                if let Err(e) = cipher::parse_cipher_extfield(cipher_str) {
                    eprintln!("FAIL: cipher extfield '{}': {}", cipher_str, e);
                    n += 1;
                }
            }
            if let Some(phc_str) = extfields.get("pbkdf") {
                if let Err(e) = pbkdf::parse_phc(phc_str) {
                    eprintln!("FAIL: pbkdf extfield '{}': {}", phc_str, e);
                    n += 1;
                }
            }
            n
        }
        etree::TextNode::BeginEnd { txt, .. } => {
            let mut n = 0;
            for child in txt {
                n += verify_node(child, paops);
            }
            n
        }
        _ => 0,
    }
}

/// Resolve the crypto policy from CommonArgs (shared by `run` and `verify_files`).
fn resolve_policy(common: &CommonArgs) -> Result<Box<dyn crypto::CryptoPolicy>> {
    let explicit_policy = common.policy.clone();
    let mut policy_name = explicit_policy
        .clone()
        .unwrap_or_else(|| consts::DEFAULT_POLICY.to_string());
    let fips = common.fips
        || (cfg!(unix)
            && match fs::read_to_string("/proc/sys/crypto/fips_enabled") {
                Ok(s) => s.starts_with('1'),
                Err(_) => false,
            });
    if fips {
        if let Some(p) = explicit_policy.as_deref()
            && p != "nist"
        {
            return Err(Error::Msg(format!(
                "Policy setting of '{}' conflicts with --fips",
                p
            )));
        }
        policy_name = "nist".to_string();
    }
    Ok(make_policy(&policy_name))
}

/// Resolve the final left/right separator strings from CLI args.
///
/// `--lang` provides a preset; explicit `-l`/`-r` flags override
/// the preset's value. The override is detected by comparing against
/// `consts::DEFAULT_*` — if the user didn't change the default, the
/// preset is used; if they did, the explicit value wins.
///
/// Single source of truth: `run()` and `apply_common()` both call
/// this. Before this helper existed, the logic was duplicated in
/// both, risking drift (TODO.finalize/32).
fn resolve_separators(common: &CommonArgs) -> (String, String) {
    if let Some(ref lang) = common.lang {
        if let Some((left, right)) = consts::lang_separators(lang) {
            let l = if common.left_separator == consts::DEFAULT_LEFT_SEP {
                left.to_string()
            } else {
                common.left_separator.clone()
            };
            let r = if common.right_separator == consts::DEFAULT_RIGHT_SEP {
                right.to_string()
            } else {
                common.right_separator.clone()
            };
            return (l, r);
        }
    }
    (
        common.left_separator.clone(),
        common.right_separator.clone(),
    )
}

/// Apply common args to ParseOps (shared by `run` and `verify_files`).
fn apply_common(common: &CommonArgs, paops: &mut ParseOps) {
    if let Some(dir) = common.casdir.clone() {
        paops.io.casdir = dir;
    } else if Path::new("cas").is_dir() {
        paops.io.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.io.casdir = Path::new(".").to_path_buf();
    }
    paops.io.verbose = common.verbose && !common.quiet;
    paops.max_depth = common.max_depth;
    let (left, right) = resolve_separators(common);
    paops.separators.left = left;
    paops.separators.right = right;
    paops.passwords.extend(common.password.clone());
}

// ===== Public-key subcommands (`keygen`, `sign`, `verify-sig`) =====
//
// These don't touch EPT markup at all; they expose the Ed25519
// primitives in `pki` as standalone commands. Future PQC variants
// (ML-DSA, composites) plug into the same subcommand surface.

fn pki_keygen(_common: CommonArgs, a: KeygenSubcmd) -> Result<()> {
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
    let (priv_pem, pub_pem) = pki::keygen(kind, &mut rng)?;
    write_key_or_stdout(a.out_priv.as_deref(), priv_pem.as_bytes())?;
    write_key_or_stdout(a.out_pub.as_deref(), pub_pem.as_bytes())?;
    Ok(())
}

fn pki_sign(_common: CommonArgs, a: SignSubcmd) -> Result<()> {
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let priv_pem = fs::read_to_string(&a.key)?;
    let msg = read_file_or_stdin(a.input.as_deref())?;
    let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
    let sig = pki::sign(kind, &priv_pem, &msg, &mut rng)?;
    let out_path = match (&a.out, &a.input) {
        (Some(p), _) => p.clone(),
        (None, Some(input)) => append_sig_ext(input),
        (None, None) => PathBuf::from("-"),
    };
    if out_path == Path::new("-") {
        std::io::stdout().write_all(&sig)?;
    } else {
        fs::write(&out_path, &sig)?;
    }
    Ok(())
}

fn pki_verify_sig(_common: CommonArgs, a: VerifySigSubcmd) -> Result<()> {
    let kind: pki::SigAlgKind = a.alg.parse()?;
    let pub_pem = fs::read_to_string(&a.key)?;
    let sig = match (&a.sig, &a.input) {
        (Some(p), _) => fs::read(p)?,
        (None, Some(input)) => fs::read(append_sig_ext(input))?,
        (None, None) => {
            return Err(Error::Msg(
                "verify-sig: no signature file or input file given".into(),
            ));
        }
    };
    let msg = read_file_or_stdin(a.input.as_deref())?;
    let ok = pki::verify(kind, &pub_pem, &msg, &sig)?;
    if ok {
        Ok(())
    } else {
        Err(Error::Msg("signature verification failed".into()))
    }
}

/// `foo.txt` → `foo.txt.sig`, `foo` → `foo.sig`. Idempotent if the
/// `.sig` extension is already present.
fn append_sig_ext(input: &Path) -> PathBuf {
    let mut p = input.to_path_buf();
    if p.extension().and_then(|e| e.to_str()) == Some("sig") {
        return p;
    }
    match p.extension() {
        Some(e) => {
            let mut new_ext = e.to_os_string();
            new_ext.push(".sig");
            p.set_extension(new_ext);
        }
        None => {
            p.set_extension("sig");
        }
    }
    p
}

fn pki_fingerprint(a: FingerprintSubcmd) -> Result<()> {
    let pem = fs::read_to_string(&a.key)?;
    let fp = capability::KeyFp::from_pem(&pem)?;
    println!("{}", fp);
    Ok(())
}

/// Compute the chain head hash of a file: SHA3-256 over the
/// canonical serialized tree. This detects ANY byte-level change —
/// content, anchors, metadata. For external pinning (publish the
/// hash out-of-band, later compare with `enprot pin`), this is the
/// strongest guarantee.
fn compute_chain_head(path: &str) -> Result<String> {
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    paops.runtime.fname = path.to_string();
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path)?))
    };
    let tree = etree::parse(reader, &mut paops)?;

    // Always hash the full canonical tree serialization. This catches
    // any tampering — content, anchors, separators, whitespace.
    let mut blob = Vec::new();
    etree::tree_write(&mut blob, &tree, &mut paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    crate::crypto::hexdigest("sha3-256", &blob, &policy)
}

fn snapshot_file(a: SnapshotSubcmd) -> Result<()> {
    let head = compute_chain_head(&a.file)?;
    println!("{}", head);
    Ok(())
}

fn pin_file(a: PinSubcmd) -> Result<()> {
    let head = compute_chain_head(&a.file)?;
    if head == a.expected {
        println!("OK");
        Ok(())
    } else {
        Err(Error::msg(format!(
            "chain head mismatch: expected {}, got {}",
            a.expected, head
        )))
    }
}

/// `audit-log` implementation: read stdin lines, append each as a
/// signed CHAIN anchor to FILE. The result is a linear, tamper-evident
/// log where each anchor's parent is the previous anchor (or empty
/// for the genesis line).
fn audit_log_stream(_common: CommonArgs, a: AuditLogSubcmd) -> Result<()> {
    let priv_pem = fs::read_to_string(&a.signer)?;

    // Read existing content (if any) → tree. Missing file = empty tree.
    let mut tree: etree::TextTree = if Path::new(&a.file).exists() {
        let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
        paops.runtime.fname = a.file.clone();
        let f = File::open(&a.file)?;
        etree::parse(BufReader::new(f), &mut paops)?
    } else {
        Vec::new()
    };

    // Find the most recent existing CHAIN anchor; new lines chain off it.
    let mut last_anchor = latest_anchor_hash(&tree);

    // Read stdin lines.
    let stdin = std::io::stdin();
    let mut line_count = 0usize;
    for line_in in stdin.lock().lines() {
        let line = line_in?;
        // Strip a trailing newline if present (lines() already does;
        // be defensive in case callers pipe raw bytes).
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        tree.push(etree::TextNode::Plain(trimmed.to_string()));

        let chain_node =
            build_chain_anchor_node_with_parent(&tree, &priv_pem, "append", "", last_anchor)?;
        // Track the new anchor's hash so the next iteration parents off it.
        if let etree::TextNode::Chain { extfields } = &chain_node {
            if let Ok(signed) = ledger::SignedAnchor::from_extfields(extfields) {
                if let Ok(h) = signed.id() {
                    last_anchor = Some(h);
                }
            }
        }
        tree.push(chain_node);
        line_count += 1;
    }

    if line_count == 0 {
        eprintln!("audit-log: no lines read from stdin; file unchanged.");
        return Ok(());
    }

    // Write the full tree back atomically.
    let tmp_path = format!("{}.tmp", a.file);
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    paops.runtime.fname = a.file.clone();
    let mut writer = BufWriter::new(File::create(&tmp_path)?);
    etree::tree_write(&mut writer, &tree, &mut paops)?;
    writer.flush()?;
    drop(writer);
    fs::rename(&tmp_path, &a.file)?;

    eprintln!("audit-log: appended {} anchor(s) to {}", line_count, a.file);
    Ok(())
}

/// Walk the tree and return the [`AnchorHash`](crate::ledger::AnchorHash)
/// of the LAST [`TextNode::Chain`] in document order, or `None` if
/// the tree has no anchors. Used by [`audit_log_stream`] to extend
/// the linear chain.
fn latest_anchor_hash(tree: &etree::TextTree) -> Option<ledger::AnchorHash> {
    let mut all = Vec::new();
    let _ = walk_for_chains(tree, &mut all);
    all.pop()
}

/// Build a [`TextNode::Chain`] signing the post-content state of
/// `tree`, with explicit `parent` (None for genesis). Used by
/// [`audit_log_stream`] where the parent is the previous anchor in
/// the stream, not all anchors in the file.
fn build_chain_anchor_node_with_parent(
    tree: &etree::TextTree,
    priv_pem: &str,
    operation: &str,
    words_csv: &str,
    parent: Option<ledger::AnchorHash>,
) -> Result<etree::TextNode> {
    use crate::ledger::{Anchor, PayloadHash, SignerId};
    use crate::pki::SigAlgKind;
    use std::collections::BTreeMap;

    // Derive pubkey from privkey.
    let botan_priv = botan::Privkey::load_pem(priv_pem).map_err(Error::botan)?;
    let botan_pub = botan_priv.pubkey().map_err(Error::botan)?;
    let pub_pem = botan_pub.pem_encode().map_err(Error::botan)?;
    let fp = capability::KeyFp::from_pem(&pub_pem)?;

    // payload_hash: SHA3-256 over EVERYTHING currently in the tree
    // (including any prior CHAIN blocks). This gives end-to-end tamper
    // detection: changing any earlier content invalidates every
    // subsequent anchor's payload. The anchor itself isn't in `tree`
    // yet (the caller pushes it AFTER this function returns), so no
    // self-reference.
    let mut paops = ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {}))?;
    let blob = etree::tree_to_blob(tree, &mut paops)?;
    let policy = crate::crypto::CryptoPolicyDefault {};
    let payload_hex = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;
    let mut payload_arr = [0u8; 32];
    payload_arr.copy_from_slice(&hex::decode(payload_hex)?);
    let payload_hash = PayloadHash(payload_arr);

    let mutations = if words_csv.is_empty() {
        operation.to_string()
    } else {
        format!("{}+{}", operation, words_csv)
    };

    let parents: Vec<_> = parent.into_iter().collect();
    let signer = SignerId::new(SigAlgKind::Ed25519, fp);
    let anchor = Anchor::builder(signer, payload_hash)
        .with_parents(parents)
        .with_mutations(mutations)
        .build();
    let signed = anchor.sign(priv_pem, &pub_pem, SigAlgKind::Ed25519)?;
    let extfields: BTreeMap<String, String> = signed.to_extfields();
    Ok(etree::TextNode::Chain { extfields })
}

/// `verify-chain` implementation: parse each file, collect CHAIN
/// blocks into an [`AnchorDag`], verify signatures against the
/// caller-supplied trust roots. Exit non-zero on any failure.
fn verify_chain_files(common: CommonArgs, a: VerifyChainSubcmd) -> Result<()> {
    // Load trust roots into a fingerprint → PEM map.
    let mut trust: HashMap<String, String> = HashMap::new();
    for pem_path in &a.trust_roots {
        let pem = fs::read_to_string(pem_path)?;
        let fp = capability::KeyFp::from_pem(&pem)?;
        trust.insert(fp.to_hex(), pem);
    }

    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let mut any_failure = false;
    for path_in in &a.files {
        let result = verify_chain_one_file(path_in, &mut paops, &trust);
        match result {
            Ok(()) => println!("OK    {}", path_in),
            Err(e) => {
                any_failure = true;
                eprintln!("FAIL  {}: {}", path_in, e);
            }
        }
    }

    if any_failure {
        Err(Error::msg("one or more files failed chain verification"))
    } else {
        Ok(())
    }
}

fn verify_chain_one_file(
    path_in: &str,
    paops: &mut ParseOps,
    trust: &HashMap<String, String>,
) -> Result<()> {
    paops.runtime.fname = path_in.into();
    let reader: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path_in).map_err(|e| {
            Error::Msg(format!("Failed to open {}: {}", path_in, e))
        })?))
    };
    let tree = etree::parse(reader, paops)?;

    // Signature + DAG verification.
    let mut dag = ledger::AnchorDag::new();
    collect_chain_anchors(&tree, &mut dag)?;
    let report = dag.verify_signatures(|fp_hex| trust.get(fp_hex).cloned());

    let mut errors: Vec<String> = Vec::new();
    for r in &report.reports {
        if !r.ok {
            if let Some(ref e) = r.error {
                errors.push(format!("{}: {}", r.id, e));
            }
        }
    }

    // Content integrity: recompute payload_hash for each CHAIN block
    // over the file state BEFORE that block (tree prefix), and compare
    // with the recorded `payload:` field. Mismatch means content was
    // tampered after the anchor was created.
    let payload_errors = verify_payload_hashes(&tree, paops)?;
    errors.extend(payload_errors);

    if !errors.is_empty() {
        return Err(Error::msg(format!(
            "{} anchor(s) failed verification: {}",
            errors.len(),
            errors.join("; ")
        )));
    }
    Ok(())
}

/// For each CHAIN block at position i, recompute SHA3-256 over
/// tree[0..i] (all nodes before this CHAIN) and compare with the
/// recorded `payload:` field. Mismatch means the file was tampered
/// after the anchor was created.
///
/// Returns a list of human-readable error strings (empty = all
/// payloads match).
fn verify_payload_hashes(tree: &etree::TextTree, paops: &mut ParseOps) -> Result<Vec<String>> {
    let policy = crate::crypto::CryptoPolicyDefault {};
    let mut errors = Vec::new();
    let mut prefix: etree::TextTree = Vec::new();

    for node in tree {
        if let etree::TextNode::Chain { extfields } = node {
            // Recompute payload over everything we've seen so far
            // (i.e., all nodes BEFORE this CHAIN).
            let blob = etree::tree_to_blob(&prefix, paops)?;
            let recomputed = crate::crypto::hexdigest("sha3-256", &blob, &policy)?;

            let recorded = extfields.get("payload").map(|s| s.as_str()).unwrap_or("");
            if recomputed != recorded {
                errors.push(format!(
                    "payload mismatch: anchor payload={} but file content hashes to {}",
                    recorded, recomputed
                ));
            }
            // The CHAIN node itself becomes part of the prefix for
            // the NEXT anchor (so tampering an anchor also breaks
            // subsequent anchors).
        }
        prefix.push(node.clone());
    }
    Ok(errors)
}

/// Walk a parsed tree and push every `TextNode::Chain` into the DAG.
/// Recurses into `BeginEnd` and `Encrypted` children; CHAIN blocks
/// typically live at the top level but can appear inside any block.
fn collect_chain_anchors(tree: &etree::TextTree, dag: &mut ledger::AnchorDag) -> Result<()> {
    for node in tree {
        match node {
            etree::TextNode::Chain { extfields } => {
                let signed = ledger::SignedAnchor::from_extfields(extfields)?;
                dag.push(signed)
                    .map_err(|e| Error::msg(format!("DAG construction failed: {}", e)))?;
            }
            etree::TextNode::BeginEnd { txt, .. } | etree::TextNode::Encrypted { txt, .. } => {
                collect_chain_anchors(txt, dag)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn read_file_or_stdin(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(p) if p != Path::new("-") => Ok(fs::read(p)?),
        _ => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_key_or_stdout(path: Option<&Path>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) if p != Path::new("-") => {
            fs::write(p, data)?;
        }
        _ => {
            std::io::stdout().write_all(data)?;
        }
    }
    Ok(())
}
