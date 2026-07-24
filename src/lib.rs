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

mod cas;
mod cipher;
mod consts;
pub mod crypto;
mod error;
mod etree;
mod pbkdf;
mod policy;
mod prot;
pub mod utils;

pub use error::{Error, Result};

use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::builder::PossibleValuesParser;
use clap::{Args, Parser, Subcommand};

use crate::etree::ParseOps;

fn make_policy(name: &str) -> Box<dyn crypto::CryptoPolicy> {
    match name {
        "default" => Box::new(crypto::CryptoPolicyDefault {}),
        "nist" => Box::new(crypto::CryptoPolicyNIST {}),
        _ => unreachable!("clap value_parser restricts to VALID_POLICIES"),
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

    /// Disable the PBKDF cache mechanism. Affects both encrypt (key
    /// derivation) and decrypt (same derivation, repeated per file).
    #[arg(long = "pbkdf-disable-cache", global = true)]
    pub pbkdf_disable_cache: bool,
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

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    std::process::exit(1);
}

pub fn app_main<I, T>(args: I)
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

fn run(common: CommonArgs, output: OutputArgs, op: Option<(EncryptOpts, Operation)>) {
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
            die(format!("Policy setting of '{}' conflicts with --fips", p));
        }
        policy_name = "nist".to_string();
    }

    let policy = make_policy(&policy_name);
    let mut paops = if let Some(defaults) = common.defaults.as_deref() {
        let mut p = ParseOps::new(make_policy(defaults));
        p.policy = policy;
        p
    } else {
        ParseOps::new(policy)
    };

    if let Some(dir) = common.casdir.clone() {
        paops.casdir = dir;
    } else if Path::new("cas").is_dir() {
        paops.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.casdir = Path::new(".").to_path_buf();
    }

    paops.verbose = common.verbose && !common.quiet;
    paops.max_depth = common.max_depth;
    paops.left_sep = common.left_separator;
    paops.right_sep = common.right_separator;
    paops.passwords.extend(common.password);
    if common.pbkdf_disable_cache {
        paops.pbkdf_cache = None;
    }

    // Apply the operation: populate the transform sets on paops. `op == None`
    // means Passthrough — leave the sets empty.
    if let Some((enc_opts, op_kind)) = op.as_ref() {
        for w in &output.word {
            match op_kind {
                Operation::Encrypt => {
                    paops.encrypt.insert(w.clone());
                }
                Operation::Decrypt => {
                    paops.decrypt.insert(w.clone());
                }
                Operation::Store => {
                    paops.store.insert(w.clone());
                }
                Operation::Fetch => {
                    paops.fetch.insert(w.clone());
                }
                Operation::EncryptStore => {
                    paops.encrypt.insert(w.clone());
                    paops.store.insert(w.clone());
                }
            }
        }

        // PBKDF + cipher options only meaningful for encrypt / encrypt-store.
        if matches!(op_kind, Operation::Encrypt | Operation::EncryptStore) {
            if let Some(alg) = enc_opts.pbkdf.as_deref() {
                paops.pbkdfopts.alg = alg.to_string();
            }
            if let Some(saltlen) = enc_opts.pbkdf_salt_len {
                paops.pbkdfopts.saltlen = saltlen;
            }
            if let Some(msec) = enc_opts.pbkdf_msec {
                paops.pbkdfopts.msec = Some(msec);
            }
            if let Some(raw) = enc_opts.pbkdf_params.as_deref() {
                paops.pbkdfopts.msec = None;
                let params: std::collections::BTreeMap<String, usize> = raw
                    .split(',')
                    .map(|kv| {
                        let (k, v) = kv.split_once('=').unwrap_or(("", "0"));
                        (k.to_string(), v.parse().unwrap_or(0))
                    })
                    .collect();
                paops.pbkdfopts.params = Some(params);
            }
            if let Some(salt_hex) = enc_opts.pbkdf_salt.as_deref() {
                paops.pbkdfopts.salt = Some(hex::decode(salt_hex).unwrap_or_else(|e| {
                    die(format!("Invalid --pbkdf-salt hex: {}", e));
                }));
            }
            if let Some(c) = enc_opts.cipher.as_deref() {
                paops.cipheropts.alg = c.to_string();
            }
            if let Some(iv_hex) = enc_opts.cipher_iv.as_deref() {
                paops.cipheropts.iv = Some(hex::decode(iv_hex).unwrap_or_else(|e| {
                    die(format!("Invalid --cipher-iv hex: {}", e));
                }));
            }
        }
    }

    if paops.verbose {
        eprintln!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.left_sep,
            paops.right_sep,
            paops.casdir.display(),
        );
    }

    let files = pair_inputs_to_outputs(
        &output.files,
        &output.output,
        &output.prefix,
        output.output_dir.as_deref(),
    );
    for (path_in, path_out) in files {
        process_one_file(&path_in, &path_out, &mut paops);
    }
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

fn process_one_file(path_in: &str, path_out: &str, paops: &mut ParseOps) {
    if paops.verbose {
        eprintln!("Reading {}", path_in);
    }

    let reader_in: Box<dyn BufRead> = if path_in == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match File::open(path_in) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => die(format!("Failed to open {} for reading: {}", path_in, e)),
        }
    };

    paops.fname = if path_in == "-" {
        "<stdin>".to_string()
    } else {
        path_in.to_string()
    };

    let tree_in = match etree::parse(reader_in, paops) {
        Ok(t) => t,
        Err(e) => die(format!("{} in {}, aborting.", e, path_in)),
    };

    if paops.verbose {
        eprintln!("Transforming {}", path_in);
    }
    let tree_out = match etree::transform(&tree_in, paops) {
        Ok(t) => t,
        Err(e) => die(format!("{} in {}, aborting.", e, path_in)),
    };

    if paops.verbose {
        eprintln!("Writing {}", path_out);
    }

    let mut writer_out: Box<dyn Write> = if path_out == "-" {
        Box::new(BufWriter::new(std::io::stdout()))
    } else {
        match File::create(path_out) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => die(format!("Failed to open {} for writing: {}", path_out, e)),
        }
    };

    if let Err(e) = etree::tree_write(&mut writer_out, &tree_out, paops) {
        die(format!("Write to {} failed: {}", path_out, e));
    }
}
