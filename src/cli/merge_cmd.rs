//! Merge-related subcommands: `merge-driver`, `resolve`, `conflicts`.
//!
//! Extracted from `cli/mod.rs` (TODO.complete/07-cli-rs-decomposition).
//! Each subcommand has its own `pub fn run(args) -> Result<()>` entry
//! point; `mod.rs` dispatches via match arms.

use std::fs::File;
use std::io::{BufReader, BufWriter, IsTerminal};

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::output;
use crate::resolve;

use super::{ConflictsSubcmd, MergeDriverSubcmd, ResolveSubcmd};

/// `merge-driver` entry point. Performs a three-way WORD-aware
/// merge and writes the result back into the "ours" path.
pub fn run_merge_driver(a: MergeDriverSubcmd) -> Result<()> {
    let conflicts = crate::merge::merge_paths(&a.base, &a.ours, &a.theirs)?;
    if conflicts > 0 {
        eprintln!(
            "merge-driver: {} conflict(s) emitted in {}",
            conflicts,
            a.ours.display()
        );
    }
    Ok(())
}

/// `resolve` entry point. Reads FILE, walks CONFLICT blocks, applies
/// the chosen mode, writes the result back to FILE in-place.
pub fn run_resolve(a: ResolveSubcmd) -> Result<()> {
    let mode = resolve::ResolveMode::from_cli_flag(&a.mode)?;
    let overrides = resolve::WordOverride::from_cli_flags(&a.word)?;
    if matches!(mode, resolve::ResolveMode::Interactive) && !std::io::stdin().is_terminal() {
        return Err(Error::InvalidArg {
            arg: "--interactive",
            reason:
                "resolve --interactive requires a TTY (pass --mode ours/theirs/both/skip for non-interactive runs)"
                    .to_string(),
        });
    };

    let policy =
        Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.runtime.fname = a.file.display().to_string();
    let f = File::open(&a.file)?;
    let tree = etree::parse(BufReader::new(f), &mut paops)?;
    let (resolved, n) = resolve::resolve_tree_with_overrides(&tree, mode, &overrides)?;
    let out = File::create(&a.file)?;
    etree::tree_write(&mut BufWriter::new(out), &resolved, &mut paops)?;
    eprintln!("resolve: cleared {} conflict(s) in {}", n, a.file.display());
    Ok(())
}

/// `conflicts` entry point: walk FILE and report unresolved
/// CONFLICT blocks. Exits non-zero if any are present.
pub fn run_conflicts(a: ConflictsSubcmd) -> Result<()> {
    let policy =
        Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.runtime.fname = a.file.display().to_string();
    let f = File::open(&a.file)?;
    let tree = etree::parse(BufReader::new(f), &mut paops)?;

    let entries: Vec<output::ConflictEntry> = tree
        .iter()
        .filter_map(|n| match n {
            etree::TextNode::Conflict { keyw, ours, theirs } => Some(output::ConflictEntry {
                word: keyw.clone(),
                ours_nodes: ours.len(),
                theirs_nodes: theirs.len(),
            }),
            _ => None,
        })
        .collect();

    let count = entries.len();
    match a.format {
        output::OutputFormat::Text => {
            if entries.is_empty() {
                println!("no conflicts in {}", a.file.display());
            } else {
                for e in &entries {
                    println!(
                        "{:<16} {} nodes ours / {} nodes theirs",
                        e.word, e.ours_nodes, e.theirs_nodes
                    );
                }
            }
        }
        output::OutputFormat::Json => {
            let payload = output::ConflictsOutput { conflicts: entries };
            println!("{}", output::to_json(&payload)?);
        }
    }

    if count > 0 {
        std::process::exit(1);
    }
    Ok(())
}
