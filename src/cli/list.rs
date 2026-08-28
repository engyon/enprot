//! `enprot list` subcommand — structural dump of EPT files.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use crate::error::{Error, Result};
use crate::etree::visitor::Control;
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

/// One non-transport node, extracted for the renderers: what it is
/// (`kind`), which WORD/hash names it, and the extfield-derived
/// values the output formats surface. The single per-kind selection
/// for both the text and JSON projections (arch review round 8);
/// renderers own spelling, skipping, and formatting.
struct Row {
    kind: RowKind,
    word: String,
    cipher: Option<String>,
    pbkdf: Option<String>,
    cas: Option<String>,
    signer: Option<String>,
    payload: Option<String>,
}

#[derive(Clone, Copy)]
enum RowKind {
    BeginEnd,
    Encrypted,
    Stored,
    Chain,
    Include,
    Conflict,
    Immutable,
    Muted,
    Key,
    Unkey,
    Cert,
    Uncert,
}

/// Extract a node's row data. `None` for Plain/Data — those are just
/// transport. Absent pbkdf/cipher stay `None`; the projections apply
/// the documented defaults, and a present-but-malformed pbkdf field
/// yields "?" (honest, instead of the old JSON answer of silently
/// reporting "legacy").
fn row_of(node: &etree::TextNode) -> Option<Row> {
    let (kind, word, extfields) = match node {
        etree::TextNode::Plain(_) | etree::TextNode::Data(_) => return None,
        etree::TextNode::BeginEnd { keyw, .. } => (RowKind::BeginEnd, keyw.clone(), None),
        etree::TextNode::Encrypted {
            keyw, extfields, ..
        } => (RowKind::Encrypted, keyw.clone(), Some(extfields)),
        etree::TextNode::Stored { keyw, cas } => {
            return Some(Row {
                kind: RowKind::Stored,
                word: keyw.clone(),
                cipher: None,
                pbkdf: None,
                cas: Some(cas.clone()),
                signer: None,
                payload: None,
            });
        }
        etree::TextNode::Chain { extfields } => {
            let view = AnchorExtFields::from_map(extfields);
            return Some(Row {
                kind: RowKind::Chain,
                word: String::new(),
                cipher: None,
                pbkdf: None,
                cas: None,
                signer: view.signer().map(str::to_string),
                payload: view.payload().map(str::to_string),
            });
        }
        etree::TextNode::Include { hash } => {
            return Some(Row {
                kind: RowKind::Include,
                word: hash.clone(),
                cipher: None,
                pbkdf: None,
                cas: None,
                signer: None,
                payload: None,
            });
        }
        etree::TextNode::Conflict { keyw, .. } => (RowKind::Conflict, keyw.clone(), None),
        etree::TextNode::Immutable { name, .. } => (RowKind::Immutable, name.clone(), None),
        etree::TextNode::Muted { name, .. } => (RowKind::Muted, name.clone(), None),
        etree::TextNode::Key { name, .. } => (RowKind::Key, name.clone(), None),
        etree::TextNode::Unkey { name } => (RowKind::Unkey, name.clone(), None),
        etree::TextNode::Cert { name, .. } => (RowKind::Cert, name.clone(), None),
        etree::TextNode::Uncert { name } => (RowKind::Uncert, name.clone(), None),
    };
    let (cipher, pbkdf) = match extfields {
        Some(map) => (
            map.get("cipher").cloned(),
            map.get("pbkdf")
                .map(|s| s.split('$').nth(1).unwrap_or("?").to_string()),
        ),
        None => (None, None),
    };
    Some(Row {
        kind,
        word,
        cipher,
        pbkdf,
        cas: None,
        signer: None,
        payload: None,
    })
}

fn trunc16(s: &str) -> &str {
    &s[..s.len().min(16)]
}

/// Print the parsed tree's block structure, one line per non-transport
/// node, indented by nesting depth. Used by `list` and `inspect`
/// (text path). A projection over [`visit_depth`] — the descent
/// lives in the visitor; only formatting lives here.
pub(super) fn list_tree<W: Write>(tree: &etree::TextTree, depth: usize, out: &mut W) -> Result<()> {
    let mut bad: Option<std::io::Error> = None;
    etree::visitor::visit_depth(tree, &mut |node, d| {
        let Some(row) = row_of(node) else {
            return Control::Continue;
        };
        let indent = "  ".repeat(d + depth);
        let line = match row.kind {
            RowKind::BeginEnd => format!("{indent}BEGIN/END  {}", row.word),
            RowKind::Encrypted => format!(
                "{indent}ENCRYPTED {}  cipher={}  pbkdf={}",
                row.word,
                row.cipher.as_deref().unwrap_or("aes-256-siv"),
                row.pbkdf.as_deref().unwrap_or("legacy"),
            ),
            RowKind::Stored => {
                let cas = row.cas.as_deref().unwrap_or_default();
                format!("{indent}STORED    {}  cas={}…", row.word, trunc16(cas))
            }
            RowKind::Chain => {
                let signer = row.signer.as_deref().unwrap_or("?");
                let payload = row.payload.as_deref().unwrap_or("?");
                format!(
                    "{indent}CHAIN     signer={signer}  payload={}…",
                    trunc16(payload)
                )
            }
            RowKind::Include => format!("{indent}INCLUDE   {}…", trunc16(&row.word)),
            RowKind::Conflict => format!("{indent}CONFLICT  {}", row.word),
            RowKind::Immutable => format!("{indent}IMMUTABLE {}", row.word),
            RowKind::Muted => format!("{indent}MUTED     {}", row.word),
            RowKind::Key => format!("{indent}KEY       {}", row.word),
            RowKind::Unkey => format!("{indent}UNKEY     {}", row.word),
            RowKind::Cert => format!("{indent}CERT      {}", row.word),
            RowKind::Uncert => format!("{indent}UNCERT    {}", row.word),
        };
        if let Err(e) = writeln!(out, "{line}") {
            bad.get_or_insert(e);
        }
        match row.kind {
            // Only regions have rows beneath them; every other kind is
            // a leaf here (the walk would only find transport below).
            RowKind::BeginEnd => Control::Continue,
            _ => Control::Prune,
        }
    });
    if let Some(e) = bad {
        return Err(e.into());
    }
    Ok(())
}

/// Flatten the parsed tree into JSON DTO nodes — a projection over
/// [`visit_depth`]: rows arrive flat with their depth, and are
/// re-nested by an explicit frame stack. Key/cert declarations stay
/// out of the JSON listing (metadata, not structure).
fn list_tree_to_nodes(tree: &etree::TextTree, depth: usize, out: &mut Vec<output::ListNode>) {
    // stack[i] collects the nodes at depth i; on returning to a
    // shallower depth the popped frame becomes the last node's
    // children (pre-order guarantees that node is the enclosing
    // region).
    let mut stack: Vec<Vec<output::ListNode>> = vec![std::mem::take(out)];
    etree::visitor::visit_depth(tree, &mut |node, d| {
        let Some(row) = row_of(node) else {
            return Control::Continue;
        };
        let leaf = match row.kind {
            RowKind::BeginEnd => false,
            RowKind::Key | RowKind::Unkey | RowKind::Cert | RowKind::Uncert => {
                // Key/cert declarations are metadata; skip in list
                // output for now. Future: surface in a separate
                // "declarations" section.
                return Control::Prune;
            }
            _ => true,
        };
        let node = output::ListNode {
            kind: match row.kind {
                RowKind::BeginEnd => "begin-end",
                RowKind::Encrypted => "encrypted",
                RowKind::Stored => "stored",
                RowKind::Chain => "chain",
                RowKind::Include => "include",
                RowKind::Conflict => "conflict",
                RowKind::Immutable => "immutable",
                RowKind::Muted => "muted",
                _ => unreachable!("filtered above"),
            },
            word: row.word.clone(),
            depth: d + depth,
            // Defaults only describe Encrypted blocks; begin-end and
            // friends never carried cipher/pbkdf fields.
            cipher: if matches!(row.kind, RowKind::Encrypted) {
                row.cipher
                    .clone()
                    .or_else(|| Some("aes-256-siv".to_string()))
            } else {
                None
            },
            pbkdf: if matches!(row.kind, RowKind::Encrypted) {
                row.pbkdf.clone().or_else(|| Some("legacy".to_string()))
            } else {
                None
            },
            cas: row.cas.clone(),
            signer: row.signer.clone(),
            payload: row.payload.clone(),
            children: Vec::new(),
        };
        while stack.len() > d + depth + 1 {
            let frame = stack.pop().expect("root frame never pops");
            stack
                .last_mut()
                .and_then(|f| f.last_mut())
                .expect("enclosing region row precedes its children")
                .children = frame;
        }
        if stack.len() < d + depth + 1 {
            stack.push(Vec::new());
        }
        stack[d + depth].push(node);
        if leaf {
            Control::Prune
        } else {
            Control::Continue
        }
    });
    while stack.len() > 1 {
        let frame = stack.pop().expect("root frame never pops");
        stack
            .last_mut()
            .and_then(|f| f.last_mut())
            .expect("enclosing region row precedes its children")
            .children = frame;
    }
    *out = stack.pop().expect("root frame");
}
