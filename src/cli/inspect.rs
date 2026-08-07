//! `enprot inspect` subcommand — combined diagnostic.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use crate::capability;
use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::ledger;
use crate::output;

use super::list::list_tree;
use super::verify_chain::collect_chain_anchors;
use super::{CommonArgs, InspectSubcmd, apply_common, capability_to_dto, resolve_policy};

/// `inspect` entry point (TODO.finalize/42): combined diagnostic.
/// Parses the file, lists structure, checks chain anchors, and
/// shows what the current flag set can do with the file. One
/// pass, one output, no file modification.
pub fn run(a: InspectSubcmd, common: CommonArgs) -> Result<()> {
    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let reader: Box<dyn BufRead> = match &a.file {
        Some(p) if p != &PathBuf::from("-") => {
            let path_str = p.display().to_string();
            paops.runtime.fname = path_str.clone();
            Box::new(BufReader::new(File::open(p).map_err(|_e| {
                Error::Io(std::io::Error::other(format!(
                    "inspect: failed to open {path_str}"
                )))
            })?))
        }
        _ => {
            paops.runtime.fname = "<stdin>".into();
            Box::new(BufReader::new(std::io::stdin()))
        }
    };

    let tree = etree::parse(reader, &mut paops)?;

    // Build the chain-anchor view (needed by both text and JSON paths).
    let mut dag = ledger::AnchorDag::new();
    collect_chain_anchors(&tree, &mut dag)?;
    let conflict_count = tree
        .iter()
        .filter(|n| matches!(n, etree::TextNode::Conflict { .. }))
        .count();
    let caps = capability::CapabilitySet::from_paops(&paops);

    match common.format {
        output::OutputFormat::Text => {
            // Section 1: structure (same as `list`)
            println!("== structure ==");
            let stdout = std::io::stdout();
            list_tree(&tree, 0, &mut stdout.lock())?;

            // Section 2: chain anchors
            println!("\n== chain anchors ==");
            if dag.is_empty() {
                println!("  (none)");
            } else {
                println!("  {} anchor(s)", dag.len());
                for (id, signed) in dag.iter() {
                    println!("    {} signer={}", id.to_hex(), signed.anchor.signer);
                }
            }

            // Section 3: conflicts
            println!("\n== conflicts ==");
            if conflict_count == 0 {
                println!("  (none)");
            } else {
                println!("  {} unresolved conflict(s)", conflict_count);
            }

            // Section 4: capabilities
            println!("\n== capabilities ==");
            for c in caps.iter_sorted() {
                println!("  {}", c);
            }
        }
        output::OutputFormat::Json => {
            // Build block summaries from the parsed tree.
            let blocks: Vec<output::InspectBlock> = tree
                .iter()
                .map(|n| match n {
                    etree::TextNode::Plain(_) => output::InspectBlock::Plain,
                    etree::TextNode::Data(_) => output::InspectBlock::Data,
                    etree::TextNode::Stored { keyw, cas } => output::InspectBlock::Stored {
                        word: keyw.clone(),
                        hash: cas.clone(),
                    },
                    etree::TextNode::Encrypted {
                        keyw, extfields, ..
                    } => output::InspectBlock::Encrypted {
                        word: keyw.clone(),
                        cipher: extfields.get("cipher").cloned(),
                        pbkdf: extfields.get("pbkdf").cloned(),
                    },
                    etree::TextNode::BeginEnd { keyw, .. } => {
                        output::InspectBlock::Begin { word: keyw.clone() }
                    }
                    etree::TextNode::Chain { extfields } => {
                        let index = extfields
                            .get("index")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        output::InspectBlock::Chain {
                            index,
                            signer: extfields.get("signer").cloned().unwrap_or_default(),
                        }
                    }
                    etree::TextNode::Immutable { name, .. } => {
                        output::InspectBlock::Immutable { word: name.clone() }
                    }
                    etree::TextNode::Muted { name, .. } => {
                        output::InspectBlock::Mutable { word: name.clone() }
                    }
                    etree::TextNode::Conflict { keyw, .. } => {
                        output::InspectBlock::Conflict { word: keyw.clone() }
                    }
                    // Other variants (Muted, BeginEnd's END side, Include) are
                    // surfaced via the variants above; no separate DTO yet.
                    _ => output::InspectBlock::Plain,
                })
                .collect();

            let chain_anchors: Vec<output::InspectChainAnchor> = dag
                .iter()
                .map(|(id, signed)| output::InspectChainAnchor {
                    id: id.to_hex(),
                    signer: signed.anchor.signer.to_string(),
                })
                .collect();

            let capabilities: Vec<output::CapabilityDto> = caps
                .iter_sorted()
                .into_iter()
                .map(capability_to_dto)
                .collect();

            let payload = output::InspectOutput {
                file: paops.runtime.fname.clone(),
                blocks,
                chain_anchors,
                conflict_count,
                capabilities,
            };
            println!("{}", output::to_json(&payload)?);
        }
    }

    if conflict_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}
