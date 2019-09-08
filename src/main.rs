// 	main.rs
//	2018-07-17	Markku-Juhani O. Saarinen <mjos@iki.fi>

mod cas;
mod etree;
mod prot;

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

// Handle command line parameters

fn main() {
    let usage = "Usage: enprot [OPTION].. [FILE]...\n\
                 \t-h -? --help    This simple help.\n\
                 \t-v              Produce more verbose output.\n\
                 \t-q              Supress unnecessary output.\n\
                 \t-l LEFT_SEP     Specify left separator in parsing.\n\
                 \t-r RIGHT_SEP    Specify right separator in parsing.\n\
                 \t-s WORD         Store (unencrypted) WORD segments to CAS.\n\
                 \t-f WORD         Fetch (unencrypted) WORD segments from CAS.\n\
                 \t-k WORD=KEY     Specify a secret KEY for WORD.\n\
                 \t-e WORD         Encrypt WORD segments.\n\
                 \t-E WORD         Encrypt and store WORD segments.\n\
                 \t-d WORD         Decrypt WORD segments.\n\
                 \t-c DIRECTORY    Directory for CAS files (default \"cas\").\n\
                 \t-p PREFIX       Use PREFIX for output filenames.\n\
                 \t-o FILE         Specify output file for previous input.\n";

    let mut files = Vec::<(String, String)>::new();
    let mut args = std::env::args().skip(1).peekable();
    let mut paops = etree::ParseOps::new();
    let mut prefix = "".to_string();

    // set casdir to cas/ if it exists

    let path = Path::new("cas");
    if path.is_dir() {
        paops.casdir = path.to_path_buf();
    }

    // parse command line

    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "-h" | "-?" | "--help" => {
                println!("{}", usage);
                // <( ENCRYPTED AUTHOR )>
                // <( DATA X417HVMRRAs6Z1xGo5yY4TxUQ2tpAHEKQ1sg9+kfku5uUikK3y2tODtsUiGqfRGW )>
                // <( DATA xUCGYFu02BCdqPM7uuX5UNvbfrLvKkj6gLYwg/cr42PJmr4o5xnw1qo= )>
                // <( END AUTHOR )>
                ::std::process::exit(0);
            }
            "-v" | "--verbose" => {
                paops.verbose = true;
            }
            "-q" | "--quiet" => {
                paops.verbose = false;
            }
            "-l" | "--left" => {
                if let Some(par) = args.next() {
                    paops.left_sep = par;
                } else {
                    eprintln!("args: -l missing left separator");
                    ::std::process::exit(1);
                }
            }
            "-r" | "--right" => {
                if let Some(par) = args.next() {
                    paops.right_sep = par;
                } else {
                    eprintln!("args: -r missing right separator");
                    ::std::process::exit(1);
                }
            }
            "-c" | "--casdir" => {
                if let Some(par) = args.next() {
                    let path = Path::new(&par);
                    if path.is_dir() {
                        paops.casdir = path.to_path_buf();
                    } else {
                        eprintln!("args: -c: '{}' is not a directory", par);
                        ::std::process::exit(1);
                    }
                } else {
                    eprintln!("args: -c missing a directory name");
                    ::std::process::exit(1);
                }
            }
            "-e" | "--encrypt" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        paops.encrypt.insert(key.to_string());
                    }
                } else {
                    eprintln!("args: -e missing a keyword");
                    ::std::process::exit(1);
                }
            }
            "-E" | "-es" | "--encrypt-store" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        paops.encrypt.insert(key.to_string());
                        paops.store.insert(key.to_string());
                    }
                } else {
                    eprintln!("args: -e missing a keyword");
                    ::std::process::exit(1);
                }
            }
            "-d" | "--decrypt" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        paops.decrypt.insert(key.to_string());
                    }
                } else {
                    eprintln!("args: -d missing a keyword");
                    ::std::process::exit(1);
                }
            }
            "-s" | "--store" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        paops.store.insert(key.to_string());
                    }
                } else {
                    eprintln!("args: -s missing a keyword");
                    ::std::process::exit(1);
                }
            }
            "-f" | "--fetch" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        paops.fetch.insert(key.to_string());
                    }
                } else {
                    eprintln!("args: -u missing a keyword");
                    ::std::process::exit(1);
                }
            }
            "-k" | "--key" => {
                if let Some(par) = args.next() {
                    for key in par.split(',') {
                        let keyval: Vec<&str> = key.split('=').collect();
                        if keyval.len() == 2 {
                            paops
                                .keys
                                .insert(keyval[0].to_string(), keyval[1].as_bytes().to_vec());
                        } else {
                            eprintln!("args: -k uses key=val pairs.");
                            ::std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("args: -k missing a secret key");
                    ::std::process::exit(1);
                }
            }
            "-p" | "--prefix" => {
                if let Some(par) = args.next() {
                    prefix = par;
                } else {
                    eprintln!("args: -p missing a paremeter");
                    ::std::process::exit(1);
                }
            }
            "-o" | "--out" => {
                if let Some(path_out) = args.next() {
                    if let Some((path_in, _)) = files.pop() {
                        // replace the output file
                        files.push((path_in, path_out));
                    } else {
                        eprintln!(
                            "args: -o needs to be after corresponding \
                             input file"
                        );
                    }
                } else {
                    eprintln!("args: -o needs output filename");
                    ::std::process::exit(1);
                }
            }
            _ => {
                files.push((arg.clone(), prefix.clone() + &arg));
            }
        }
    }

    // print some of the processing parameters if verbose

    if paops.verbose {
        println!(
            "LEFT_SEP='{}' RIGHT_SEP='{}' casdir = '{}'",
            paops.left_sep,
            paops.right_sep,
            paops.casdir.display()
        );
    }

    // process all files

    for (path_in, path_out) in files {
        if paops.verbose {
            println!("Reading {}", path_in);
        }

        // open input file
        let reader_in = match File::open(&path_in) {
            Ok(file_in) => BufReader::new(file_in),
            Err(e) => {
                eprintln!("Failed to open {} for reading: {}", path_in, e);
                ::std::process::exit(1);
            }
        };

        // parse input
        paops.fname = path_in.to_string();
        let tree_in = match etree::parse(reader_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };

        // transform it
        if paops.verbose {
            println!("Transforming {}", path_in);
        }
        let tree_out = match etree::transform(tree_in, &mut paops) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{} in {}, aborting.", e, path_in);
                ::std::process::exit(1);
            }
        };

        // write it out
        if paops.verbose {
            println!("Writing {}", path_out);
        }

        // open output file
        let mut writer_out = match File::create(&path_out) {
            Ok(file_out) => BufWriter::new(file_out),
            Err(e) => {
                eprintln!("Failed to open {} for writing: {}", path_out, e);
                ::std::process::exit(1);
            }
        };

        etree::tree_write(&mut writer_out, &tree_out, &mut paops);
    }
}
