// Copyright (c) 2018-2020 [Ribose Inc](https://www.ribose.com).
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

extern crate aes;
extern crate aes_gcm_siv;
extern crate block_cipher_trait;
extern crate botan;
extern crate clap;
extern crate hex;
extern crate num;
extern crate phc;
extern crate phf;
extern crate rpassword;

mod cas;
mod cipher;
mod consts;
pub mod crypto;
mod etree;
mod pbkdf;
mod policy;
mod prot;
pub mod utils;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use clap::{App, AppSettings, Arg, ArgSettings, ErrorKind};

fn validate_positive<T>(v: String) -> Result<(), String>
where
    T: std::str::FromStr + num::Unsigned,
{
    let err = format!("Expected a number > 0, received '{}'", v);
    v.parse::<T>()
        .map_err(|_| err.clone())
        .and_then(|n| if n != T::zero() { Ok(()) } else { Err(err) })
}

fn validate_non_negative<T>(v: String) -> Result<(), String>
where
    T: std::str::FromStr + num::Unsigned,
{
    let err = format!("Expected a number 0 or greater, received '{}'", v);
    v.parse::<T>().map_err(|_| err.clone()).map(|_| ())
}

fn err_exit(app: &mut App, desc: &str, kind: ErrorKind, show_help: bool) -> ! {
    if show_help {
        app.print_help().unwrap();
        eprintln!("");
    }
    let err = clap::Error::with_description(desc, kind);
    eprintln!("{}", err);
    std::process::exit(1);
}

fn make_policy(app: &mut App, name: &str) -> Box<dyn crypto::CryptoPolicy> {
    match name {
        "default" => Box::new(crypto::CryptoPolicyDefault {}),
        "nist" => Box::new(crypto::CryptoPolicyNIST {}),
        value => {
            // shouldn't happen
            err_exit(
                app,
                &format!("Invalid policy: '{}'", value),
                ErrorKind::InvalidValue,
                true,
            );
        }
    }
}

// Handle command line parameters

pub fn app_main<I, T>(args: I)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // <( ENCRYPTED AUTHOR )>
    // <( DATA X417HVMRRAs6Z1xGo5yY4TxUQ2tpAHEKQ1sg9+kfku5uUikK3y2tODtsUiGqfRGW )>
    // <( DATA xUCGYFu02BCdqPM7uuX5UNvbfrLvKkj6gLYwg/cr42PJmr4o5xnw1qo= )>
    // <( END AUTHOR )>

    const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    let default_max_depth = consts::DEFAULT_MAX_DEPTH.to_string();

    let mut app = App::new("enprot")
        .version(VERSION)
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ColorAuto)
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Produce more verbose output"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Suppress unnecessary output"),
        )
        .arg(
            Arg::with_name("max-depth")
                .long("max-depth")
                .takes_value(true)
                .value_name("DEPTH")
                .validator(validate_non_negative::<usize>)
                .default_value(&default_max_depth)
                .help("Maximum recursion depth (use 0 for infinite)"),
        )
        .arg(
            Arg::with_name("left-separator")
                .short("l")
                .long("left-separator")
                .takes_value(true)
                .value_name("SEP")
                .default_value(consts::DEFAULT_LEFT_SEP)
                .help("Specify left separator in parsing"),
        )
        .arg(
            Arg::with_name("right-separator")
                .short("r")
                .long("right-separator")
                .takes_value(true)
                .value_name("SEP")
                .default_value(consts::DEFAULT_RIGHT_SEP)
                .help("Specify right separator in parsing"),
        )
        .arg(
            Arg::with_name("store")
                .short("s")
                .long("store")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Store (unencrypted) WORD segments to CAS"),
        )
        .arg(
            Arg::with_name("fetch")
                .short("f")
                .long("fetch")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Fetch (unencrypted) WORD segments to CAS"),
        )
        .arg(
            Arg::with_name("password")
                .short("k")
                .long("key")
                .takes_value(true)
                .value_name("WORD=PASSWORD")
                .multiple(true)
                .number_of_values(1)
                .validator(|v: String| -> Result<(), String> {
                    for val in v.split(",") {
                        let wordpass = val.splitn(2, '=').collect::<Vec<&str>>();
                        if wordpass.len() != 2 || wordpass[0].len() == 0 || wordpass[1].len() == 0 {
                            return Err(String::from(
                                "Must be of the form WORD=PASSWORD[,WORD=PASSWORD]",
                            ));
                        }
                    }
                    Ok(())
                })
                .help("Specify a secret PASSWORD for WORD"),
        )
        .arg(
            Arg::with_name("encrypt")
                .short("e")
                .long("encrypt")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Encrypt WORD segments"),
        )
        .arg(
            Arg::with_name("encrypt-store")
                .short("E")
                .long("encrypt-store")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Encrypt and store WORD segments"),
        )
        .arg(
            Arg::with_name("policy")
                .long("policy")
                .takes_value(true)
                .value_name("POLICY")
                .default_value(consts::DEFAULT_POLICY)
                .possible_values(consts::VALID_POLICIES)
                .help("Set the policy to restrict cryptographic algorithms"),
        )
        .arg(
            Arg::with_name("defaults")
                .long("defaults")
                .takes_value(true)
                .value_name("POLICY")
                .possible_values(consts::VALID_POLICIES)
                .help("Load settings from POLICY, but do not enforce the policy"),
        )
        .arg(Arg::with_name("fips").long("fips").help(
            "Select and enforce the use of FIPS-compliant algorithms (implies --policy=nist)",
        ))
        .arg(
            Arg::with_name("pbkdf")
                .long("pbkdf")
                .takes_value(true)
                .value_name("ALG")
                .possible_values(consts::VALID_PBKDF_ALGS)
                .help("Set the PBKDF algorithm to use when encrypting"),
        )
        .arg(
            Arg::with_name("pbkdf-msec")
                .long("pbkdf-msec")
                .takes_value(true)
                .value_name("MSEC")
                .validator(validate_positive::<u32>)
                .help("Set the millisecond count for the PBKDF algorithm"),
        )
        .arg(
            Arg::with_name("pbkdf-salt-len")
                .long("pbkdf-salt-len")
                .takes_value(true)
                .value_name("BYTES")
                .validator(&validate_positive::<usize>)
                .help("Set the salt length for the PBKDF"),
        )
        .arg(
            Arg::with_name("pbkdf-params")
                .long("pbkdf-params")
                .takes_value(true)
                .value_name("PARAMS")
                .hidden(true)
                .help("Advanced option for testing, do not use"),
        )
        .arg(
            Arg::with_name("pbkdf-salt")
                .long("pbkdf-salt")
                .takes_value(true)
                .value_name("HEX")
                .hidden(true)
                .help("Advanced option for testing, do not use"),
        )
        .arg(
            Arg::with_name("pbkdf-disable-cache")
                .long("pbkdf-disable-cache")
                .help("Disable the PBKDF cache mechanism"),
        )
        .arg(
            Arg::with_name("cipher")
                .long("cipher")
                .takes_value(true)
                .value_name("ALG")
                .possible_values(consts::VALID_CIPHER_ALGS)
                .help("Set the cipher algorithm to use when encrypting"),
        )
        .arg(
            Arg::with_name("cipher-iv")
                .long("cipher-iv")
                .takes_value(true)
                .value_name("ALG")
                .hidden(true)
                .help("Advanced option for testing, do not use"),
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .takes_value(true)
                .value_name("WORD")
                .multiple(true)
                .number_of_values(1)
                .help("Decrypt WORD segments"),
        )
        .arg(
            Arg::with_name("casdir")
                .short("c")
                .long("casdir")
                .takes_value(true)
                .value_name("DIRECTORY")
                .default_value("./")
                .set(ArgSettings::HideDefaultValue)
                .validator(|v: String| -> Result<(), String> {
                    if Path::new(&v).is_dir() {
                        return Ok(());
                    } else {
                        Err(String::from("Must be a directory"))
                    }
                })
                .help("Directory for CAS files (default \"cas\" if exists, else \".\")"),
        )
        .arg(
            Arg::with_name("prefix")
                .short("p")
                .long("prefix")
                .takes_value(true)
                .value_name("PREFIX")
                .default_value("")
                .set(ArgSettings::HideDefaultValue)
                .set(ArgSettings::EmptyValues)
                .help("Use PREFIX for output filenames"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .value_name("FILE")
                .multiple(true)
                .number_of_values(1)
                .help("Specify output file for previous input"),
        )
        .arg(
            Arg::with_name("input")
                .required(true)
                .index(1)
                .value_name("FILE")
                .default_value("-")
                .multiple(true)
                .help("The input file(s)"),
        );
    let matches = app.clone().get_matches_from(args);

    let mut policy = matches.value_of("policy").unwrap();
    // check if fips mode is requested (implicitly or explicitly)
    let fips = matches.occurrences_of("fips") != 0
        || (cfg!(unix)
            && match fs::read_to_string("/proc/sys/crypto/fips_enabled") {
                Ok(str) => str.chars().next() == Some('1'),
                Err(_) => false,
            });
    if fips {
        // check if the user specified a conflicting policy
        if matches.occurrences_of("policy") != 0 && policy != "nist" {
            err_exit(
                &mut app,
                &format!("Policy setting of '{}' conflicts with --fips", policy),
                ErrorKind::ArgumentConflict,
                false,
            );
        }
        // override policy
        policy = "nist";
    }
    assert!(!fips || (fips && policy == "nist"));
    // instantiate the actual policy
    let policy = make_policy(&mut app, policy);

    // the policy will set default crypto-related values
    let mut paops;
    if let Some(defaults) = matches.value_of("defaults") {
        paops = etree::ParseOps::new(make_policy(&mut app, defaults));
        paops.policy = policy;
    } else {
        paops = etree::ParseOps::new(policy);
    }

    // casdir
    if matches.occurrences_of("casdir") == 0 && Path::new("cas").is_dir() {
        paops.casdir = Path::new("cas").to_path_buf();
    } else {
        paops.casdir = Path::new(matches.value_of("casdir").unwrap()).to_path_buf();
    }
    // verbosity
    paops.verbose = matches.occurrences_of("verbose") != 0;
    if matches.occurrences_of("quiet") != 0 {
        paops.verbose = false;
    }
    // max recursion depth
    paops.max_depth = matches
        .value_of("max-depth")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    // separators
    paops.left_sep = matches.value_of("left-separator").unwrap().to_string();
    paops.right_sep = matches.value_of("right-separator").unwrap().to_string();
    // transforms arguments like ["a", "b,c", "d"] into ["a", "b", "c", "d"]
    macro_rules! csep_arg {
        ( $set:expr, $name:expr ) => {
            $set.extend(
                matches
                    .values_of($name)
                    .unwrap_or(clap::Values::default())
                    .flat_map(|arg| arg.split(",").map(|val| val.to_string()))
                    .collect::<Vec<String>>(),
            );
        };
    }
    // expand comma-separated args
    csep_arg!(paops.store, "store");
    csep_arg!(paops.fetch, "fetch");
    csep_arg!(paops.encrypt, "encrypt");
    csep_arg!(paops.encrypt, "encrypt-store");
    csep_arg!(paops.store, "encrypt-store");
    csep_arg!(paops.decrypt, "decrypt");
    // password
    // ["word1=pass1", "word2=pass2,word3=pass3"] ->
    //   [(word1, pass1), (word2, pass2), (word3, pass3)]
    paops.passwords.extend(
        matches
            .values_of("password")
            .unwrap_or(clap::Values::default())
            .flat_map(|arg| {
                arg.split(",").map(|val| {
                    let wordpass = val.splitn(2, '=').collect::<Vec<&str>>();
                    (wordpass[0].to_string(), wordpass[1].to_string())
                })
            }),
    );

    // pbkdf
    if let Some(pbkdf) = matches.value_of("pbkdf") {
        paops.pbkdfopts.alg = pbkdf.to_string();
    }
    if let Some(saltlen) = matches.value_of("pbkdf-salt-len") {
        paops.pbkdfopts.saltlen = saltlen.parse::<usize>().unwrap();
    }
    if let Some(msec) = matches.value_of("pbkdf-msec") {
        paops.pbkdfopts.msec = Some(msec.parse::<u32>().unwrap());
    }
    if let Some(val) = matches.value_of("pbkdf-params") {
        paops.pbkdfopts.msec = None;
        let mut params: BTreeMap<String, usize> = BTreeMap::new();
        params.extend(val.split(",").map(|val| {
            let parts = val.splitn(2, '=').collect::<Vec<&str>>();
            (parts[0].to_string(), parts[1].parse::<usize>().unwrap())
        }));
        paops.pbkdfopts.params = Some(params);
    }
    if let Some(val) = matches.value_of("pbkdf-salt") {
        paops.pbkdfopts.salt = Some(hex::decode(val).unwrap());
    }
    if matches.occurrences_of("pbkdf-disable-cache") != 0 {
        paops.pbkdf_cache = None;
    }
    // cipher
    if let Some(cipher) = matches.value_of("cipher") {
        paops.cipheropts.alg = cipher.to_string();
    }
    if let Some(iv) = matches.value_of("cipher-iv") {
        paops.cipheropts.iv = Some(hex::decode(iv).unwrap());
    }

    // print some of the processing parameters if verbose
    if paops.verbose {
        eprintln!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.left_sep,
            paops.right_sep,
            paops.casdir.display(),
        );
    }

    // process all files
    let mut files = Vec::<(String, String)>::new();
    let prefix = matches.value_of("prefix").unwrap();
    let mut outiter = matches
        .values_of("output")
        .unwrap_or(clap::Values::default());
    for input in matches.values_of("input").unwrap() {
        if let Some(output) = outiter.next() {
            files.push((input.to_string(), output.to_string()));
        } else {
            let mut output = prefix.to_string() + &input;
            if input == "-" {
                output = "-".to_string();
            }
            files.push((input.to_string(), output));
        }
    }

    for (path_in, path_out) in files {
        if paops.verbose {
            eprintln!("Reading {}", path_in);
        }

        // open input file
        let reader_in: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            match File::open(&path_in) {
                Ok(file_in) => Box::new(BufReader::new(file_in)),
                Err(e) => {
                    eprintln!("Failed to open {} for reading: {}", path_in, e);
                    ::std::process::exit(1);
                }
            }
        };

        // parse input
        paops.fname = if path_in == "-" {
            "<stdin>".to_string()
        } else {
            path_in.to_string()
        };
        let tree_in = match etree::parse(reader_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };

        // transform it
        if paops.verbose {
            eprintln!("Transforming {}", path_in);
        }
        let tree_out = match etree::transform(&tree_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };

        // write it out
        if paops.verbose {
            eprintln!("Writing {}", path_out);
        }

        // open output file
        let mut writer_out: Box<dyn Write> = if path_out == "-" {
            Box::new(BufWriter::new(std::io::stdout()))
        } else {
            match File::create(&path_out) {
                Ok(file_out) => Box::new(BufWriter::new(file_out)),
                Err(e) => {
                    eprintln!("Failed to open {} for writing: {}", path_out, e);
                    ::std::process::exit(1);
                }
            }
        };

        etree::tree_write(&mut writer_out, &tree_out, &mut paops);
    }
}
