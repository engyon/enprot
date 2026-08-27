//! `enprot list` subcommand — structural dump of EPT files.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps};
use crate::extfield::AnchorExtFields;
use crate::output;

use super::pipeline::pair_inputs_to_outputs;
use super::{CommonArgs, OutputArgs, common::apply_common, common::resolve_policy};

/// `list` entry point: parse each input file and dump its block
/// structure (BeginEnd/Encrypted/Stored/Chain/Conflict/etc.) to text
/// or JSON. Skips Plain/Data nodes — those are just transport.
pub fn run(common: CommonArgs, output_args: OutputArgs) -> Result<()> {
    let policy = resolve_policy(&common)?;
    let mut paops = ParseOps::new(policy)?;
    apply_common(&common, &mut paops);

    let files = pair_inputs_to_outputs(
        &output_args.files,
        &output_args.output,
        &output_args.prefix,
        output_args.output_dir.as_deref(),
    );

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut json_listings: Vec<output::FileListing> = Vec::new();

    for (path_in, _) in &files {
        let reader: Box<dyn BufRead> = if path_in == "-" {
            Box::new(BufReader::new(std::io::stdin()))
        } else {
            Box::new(BufReader::new(File::open(path_in).map_err(|e| {
                Error::Io(std::io::Error::other(format!(
                    "Failed to open {path_in}: {e}"
                )))
            })?))
        };
        paops.runtime.fname = path_in.clone();

        let tree = etree::parse(reader, &mut paops)?;

        match common.format {
            output::OutputFormat::Text => {
                if files.len() > 1 {
                    writeln!(out, "== {} ==", path_in)?;
                }
                list_tree(&tree, 0, &mut out)?;
            }
            output::OutputFormat::Json => {
                let mut nodes = Vec::new();
                list_tree_to_nodes(&tree, 0, &mut nodes);
                json_listings.push(output::FileListing {
                    path: path_in.clone(),
                    nodes,
                });
            }
        }
    }

    if matches!(common.format, output::OutputFormat::Json) {
        let payload = output::ListOutput {
            files: json_listings,
        };
        writeln!(out, "{}", output::to_json(&payload)?)?;
    }
    Ok(())
}

/// Recursively print the parsed tree's block structure with one line
/// per non-transport node. Used by `list` and `inspect` (text path).
pub(super) fn list_tree<W: Write>(tree: &etree::TextTree, depth: usize, out: &mut W) -> Result<()> {
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
                let view = AnchorExtFields::from_map(extfields);
                let signer = view.signer().unwrap_or("?");
                let payload = view.payload().unwrap_or("?");
                let short_payload = &payload[..payload.len().min(16)];
                writeln!(
                    out,
                    "{}CHAIN     signer={}  payload={}…",
                    indent, signer, short_payload
                )?;
            }
            etree::TextNode::Include { hash } => {
                writeln!(out, "{}INCLUDE   {}…", indent, &hash[..hash.len().min(16)])?;
            }
            etree::TextNode::Conflict { keyw, .. } => {
                writeln!(out, "{}CONFLICT  {}", indent, keyw)?;
            }
            etree::TextNode::Immutable { name, .. } => {
                writeln!(out, "{}IMMUTABLE {}", indent, name)?;
            }
            etree::TextNode::Muted { name, .. } => {
                writeln!(out, "{}MUTED     {}", indent, name)?;
            }
            etree::TextNode::Key { name, .. } => {
                writeln!(out, "{}KEY       {}", indent, name)?;
            }
            etree::TextNode::Unkey { name } => {
                writeln!(out, "{}UNKEY     {}", indent, name)?;
            }
            etree::TextNode::Cert { name, .. } => {
                writeln!(out, "{}CERT      {}", indent, name)?;
            }
            etree::TextNode::Uncert { name } => {
                writeln!(out, "{}UNCERT    {}", indent, name)?;
            }
        }
    }
    Ok(())
}

/// Flatten the parsed tree into JSON DTO nodes. Same selection logic
/// as [`list_tree`] (skips Plain/Data); recurses into BeginEnd.
fn list_tree_to_nodes(tree: &etree::TextTree, depth: usize, out: &mut Vec<output::ListNode>) {
    for node in tree {
        match node {
            etree::TextNode::BeginEnd { keyw, txt } => {
                let mut children = Vec::new();
                list_tree_to_nodes(txt, depth + 1, &mut children);
                out.push(output::ListNode {
                    kind: "begin-end",
                    word: keyw.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: None,
                    payload: None,
                    children,
                });
            }
            etree::TextNode::Encrypted {
                keyw, extfields, ..
            } => {
                let cipher = extfields
                    .get("cipher")
                    .cloned()
                    .or_else(|| Some("aes-256-siv".to_string()));
                let pbkdf = extfields
                    .get("pbkdf")
                    .and_then(|s| s.split('$').nth(1).map(String::from))
                    .or_else(|| Some("legacy".to_string()));
                out.push(output::ListNode {
                    kind: "encrypted",
                    word: keyw.clone(),
                    depth,
                    cipher,
                    pbkdf,
                    cas: None,
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Stored { keyw, cas } => {
                out.push(output::ListNode {
                    kind: "stored",
                    word: keyw.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: Some(cas.clone()),
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Plain(_) | etree::TextNode::Data(_) => {}
            etree::TextNode::Chain { extfields } => {
                out.push(output::ListNode {
                    kind: "chain",
                    word: String::new(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: AnchorExtFields::from_map(extfields)
                        .signer()
                        .map(str::to_string),
                    payload: AnchorExtFields::from_map(extfields)
                        .payload()
                        .map(str::to_string),
                    children: Vec::new(),
                });
            }
            etree::TextNode::Include { hash } => {
                out.push(output::ListNode {
                    kind: "include",
                    word: hash.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Conflict { keyw, .. } => {
                out.push(output::ListNode {
                    kind: "conflict",
                    word: keyw.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Immutable { name, .. } => {
                out.push(output::ListNode {
                    kind: "immutable",
                    word: name.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Muted { name, .. } => {
                out.push(output::ListNode {
                    kind: "muted",
                    word: name.clone(),
                    depth,
                    cipher: None,
                    pbkdf: None,
                    cas: None,
                    signer: None,
                    payload: None,
                    children: Vec::new(),
                });
            }
            etree::TextNode::Key { .. }
            | etree::TextNode::Unkey { .. }
            | etree::TextNode::Cert { .. }
            | etree::TextNode::Uncert { .. } => {
                // Key/cert declarations are metadata; skip in list output
                // for now. Future: surface in a separate "declarations"
                // section.
            }
        }
    }
}
