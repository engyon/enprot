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

use clap::Parser;
use clap::builder::PossibleValuesParser;

fn make_policy(name: &str) -> Box<dyn crypto::CryptoPolicy> {
    match name {
        "default" => Box::new(crypto::CryptoPolicyDefault {}),
        "nist" => Box::new(crypto::CryptoPolicyNIST {}),
        _ => unreachable!("clap value_parser restricts to VALID_POLICIES"),
    }
}

#[derive(Parser)]
#[command(
    name = "enprot",
    version,
    about = "Engyon Protected Text (EPT) confidentiality processor"
)]
pub struct Cli {
    /// Produce more verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Suppress unnecessary output.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Maximum recursion depth (use 0 for infinite).
    #[arg(long, default_value_t = consts::DEFAULT_MAX_DEPTH)]
    pub max_depth: usize,

    /// Specify left separator in parsing.
    #[arg(short = 'l', long, default_value = consts::DEFAULT_LEFT_SEP)]
    pub left_separator: String,

    /// Specify right separator in parsing.
    #[arg(short = 'r', long, default_value = consts::DEFAULT_RIGHT_SEP)]
    pub right_separator: String,

    /// Store (unencrypted) WORD segments to CAS.
    #[arg(short = 's', long, value_name = "WORD", value_delimiter = ',')]
    pub store: Vec<String>,

    /// Fetch (unencrypted) WORD segments from CAS.
    #[arg(short = 'f', long, value_name = "WORD", value_delimiter = ',')]
    pub fetch: Vec<String>,

    /// Encrypt WORD segments.
    #[arg(short = 'e', long, value_name = "WORD", value_delimiter = ',')]
    pub encrypt: Vec<String>,

    /// Encrypt and store WORD segments.
    #[arg(
        short = 'E',
        long = "encrypt-store",
        value_name = "WORD",
        value_delimiter = ','
    )]
    pub encrypt_store: Vec<String>,

    /// Decrypt WORD segments.
    #[arg(short = 'd', long, value_name = "WORD", value_delimiter = ',')]
    pub decrypt: Vec<String>,

    /// Specify a secret PASSWORD for WORD (format: WORD=PASSWORD).
    #[arg(short = 'k', long = "key", value_name = "WORD=PASSWORD",
          value_delimiter = ',', value_parser = parse_word_password)]
    pub password: Vec<(String, String)>,

    /// Set the policy to restrict cryptographic algorithms.
    #[arg(long, value_parser = PossibleValuesParser::new(consts::VALID_POLICIES.to_vec()))]
    pub policy: Option<String>,

    /// Load settings from POLICY, but do not enforce the policy.
    #[arg(long, value_parser = PossibleValuesParser::new(consts::VALID_POLICIES.to_vec()))]
    pub defaults: Option<String>,

    /// Select and enforce the use of FIPS-compliant algorithms (implies --policy=nist).
    #[arg(long)]
    pub fips: bool,

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

    /// Disable the PBKDF cache mechanism.
    #[arg(long = "pbkdf-disable-cache")]
    pub pbkdf_disable_cache: bool,

    /// Set the cipher algorithm to use when encrypting.
    #[arg(long, value_parser = PossibleValuesParser::new(consts::VALID_CIPHER_ALGS.to_vec()))]
    pub cipher: Option<String>,

    /// Advanced option for testing, do not use.
    #[arg(long, value_name = "ALG", hide = true)]
    pub cipher_iv: Option<String>,

    /// Directory for CAS files (default "cas" if it exists, else ".").
    #[arg(short = 'c', long, value_name = "DIRECTORY", value_parser = parse_casdir)]
    pub casdir: Option<PathBuf>,

    /// Use PREFIX for output filenames.
    #[arg(short = 'p', long, default_value = "", allow_hyphen_values = true)]
    pub prefix: String,

    /// Specify output file for previous input.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Vec<String>,

    /// The input file(s).
    #[arg(value_name = "FILE", default_value = "-")]
    pub input: Vec<String>,
}

fn parse_word_password(s: &str) -> std::result::Result<(String, String), String> {
    let mut it = s.splitn(2, '=');
    let word = it.next().unwrap_or("");
    let pass = it.next().unwrap_or("");
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

    // Resolve the policy. If --policy was not given, fall back to the default.
    let explicit_policy = cli.policy.clone();
    let mut policy_name = explicit_policy
        .clone()
        .unwrap_or_else(|| consts::DEFAULT_POLICY.to_string());

    // Resolve FIPS interaction. --fips forces NIST; on Linux, also auto-engages
    // when /proc/sys/crypto/fips_enabled reads 1. An explicit non-NIST policy
    // is rejected when FIPS is in effect.
    let fips = cli.fips
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

    let mut paops = if let Some(defaults) = cli.defaults.as_deref() {
        let mut p = etree_parse_ops_from(make_policy(defaults));
        p.policy = policy;
        p
    } else {
        etree_parse_ops_from(policy)
    };

    // casdir: explicit flag wins; else ./cas if it exists; else "."
    if let Some(dir) = cli.casdir.clone() {
        paops.casdir = dir;
    } else if Path::new("cas").is_dir() {
        paops.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.casdir = Path::new(".").to_path_buf();
    }

    paops.verbose = cli.verbose && !cli.quiet;
    paops.max_depth = cli.max_depth;
    paops.left_sep = cli.left_separator;
    paops.right_sep = cli.right_separator;

    // encrypt-store implies both encrypt and store
    paops.store.extend(cli.store.iter().cloned());
    paops.fetch.extend(cli.fetch.iter().cloned());
    paops.encrypt.extend(cli.encrypt.iter().cloned());
    paops.encrypt.extend(cli.encrypt_store.iter().cloned());
    paops.store.extend(cli.encrypt_store.iter().cloned());
    paops.decrypt.extend(cli.decrypt.iter().cloned());

    paops.passwords.extend(cli.password.iter().cloned());

    // PBKDF options
    if let Some(alg) = cli.pbkdf.as_deref() {
        paops.pbkdfopts.alg = alg.to_string();
    }
    if let Some(saltlen) = cli.pbkdf_salt_len {
        paops.pbkdfopts.saltlen = saltlen;
    }
    if let Some(msec) = cli.pbkdf_msec {
        paops.pbkdfopts.msec = Some(msec);
    }
    if let Some(raw) = cli.pbkdf_params.as_deref() {
        paops.pbkdfopts.msec = None;
        let params: std::collections::BTreeMap<String, usize> = raw
            .split(',')
            .map(|kv| {
                let mut it = kv.splitn(2, '=');
                let k = it.next().unwrap_or("");
                let v: usize = it.next().unwrap_or("0").parse().unwrap_or(0);
                (k.to_string(), v)
            })
            .collect();
        paops.pbkdfopts.params = Some(params);
    }
    if let Some(salt_hex) = cli.pbkdf_salt.as_deref() {
        paops.pbkdfopts.salt = Some(hex::decode(salt_hex).unwrap_or_else(|e| {
            die(format!("Invalid --pbkdf-salt hex: {}", e));
        }));
    }
    if cli.pbkdf_disable_cache {
        paops.pbkdf_cache = None;
    }

    // Cipher options
    if let Some(c) = cli.cipher.as_deref() {
        paops.cipheropts.alg = c.to_string();
    }
    if let Some(iv_hex) = cli.cipher_iv.as_deref() {
        paops.cipheropts.iv = Some(hex::decode(iv_hex).unwrap_or_else(|e| {
            die(format!("Invalid --cipher-iv hex: {}", e));
        }));
    }

    if paops.verbose {
        eprintln!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.left_sep,
            paops.right_sep,
            paops.casdir.display(),
        );
    }

    // Pair each input with an output. -o consumes in order; remaining inputs
    // get prefix + input name (or "-" if input is "-").
    let mut files: Vec<(String, String)> = Vec::new();
    let mut out_iter = cli.output.iter();
    for input in cli.input.iter() {
        if let Some(output) = out_iter.next() {
            files.push((input.clone(), output.clone()));
        } else {
            let output = if input == "-" {
                "-".to_string()
            } else {
                format!("{}{}", cli.prefix, input)
            };
            files.push((input.clone(), output));
        }
    }

    for (path_in, path_out) in files {
        if paops.verbose {
            eprintln!("Reading {}", path_in);
        }

        let reader_in: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            match File::open(&path_in) {
                Ok(f) => Box::new(BufReader::new(f)),
                Err(e) => die(format!("Failed to open {} for reading: {}", path_in, e)),
            }
        };

        paops.fname = if path_in == "-" {
            "<stdin>".to_string()
        } else {
            path_in.clone()
        };

        let tree_in = match etree::parse(reader_in, &mut paops) {
            Ok(t) => t,
            Err(e) => die(format!("{} in {}, aborting.", e, path_in)),
        };

        if paops.verbose {
            eprintln!("Transforming {}", path_in);
        }
        let tree_out = match etree::transform(&tree_in, &mut paops) {
            Ok(t) => t,
            Err(e) => die(format!("{} in {}, aborting.", e, path_in)),
        };

        if paops.verbose {
            eprintln!("Writing {}", path_out);
        }

        let mut writer_out: Box<dyn Write> = if path_out == "-" {
            Box::new(BufWriter::new(std::io::stdout()))
        } else {
            match File::create(&path_out) {
                Ok(f) => Box::new(BufWriter::new(f)),
                Err(e) => die(format!("Failed to open {} for writing: {}", path_out, e)),
            }
        };

        etree::tree_write(&mut writer_out, &tree_out, &mut paops);
    }
}

fn etree_parse_ops_from(policy: Box<dyn crypto::CryptoPolicy>) -> etree::ParseOps {
    etree::ParseOps::new(policy)
}
