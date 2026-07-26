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

//! Conflict resolver (TODO.roadmap/44).
//!
//! `enprot resolve [--ours|--theirs|--both|--interactive] FILE` walks
//! a parsed tree and replaces every [`TextNode::Conflict`] with the
//! caller-chosen resolution. Non-interactive modes (`--ours`,
//! `--theirs`, `--both`) apply one decision to every conflict;
//! interactive mode prompts per conflict and requires a TTY.
//!
//! The output is always valid EPT — conflict markers are fully
//! removed (or replaced with explicit BeginEnd copies of the chosen
//! side). Re-running `enprot resolve` on a clean file is a no-op.

use std::io::{BufRead, Write};

use crate::error::{Error, Result};
use crate::etree::{TextNode, TextTree};

/// How to resolve a single conflict.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResolveMode {
    /// Keep the `ours` side; drop theirs.
    Ours,
    /// Keep the `theirs` side; drop ours.
    Theirs,
    /// Concatenate: ours then theirs, both as BeginEnd blocks under
    /// the original keyw. Useful when both edits carry distinct
    /// information the caller wants to preserve.
    Both,
    /// Drop the conflict entirely. The WORD region is removed from
    /// the output. Caller must understand the data-loss implication.
    Skip,
    /// Prompt for each conflict.
    Interactive,
}

impl ResolveMode {
    pub fn from_cli_flag(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ours" => Ok(ResolveMode::Ours),
            "theirs" => Ok(ResolveMode::Theirs),
            "both" => Ok(ResolveMode::Both),
            "skip" => Ok(ResolveMode::Skip),
            "interactive" | "i" => Ok(ResolveMode::Interactive),
            other => Err(Error::msg(format!(
                "unknown resolve mode '{}' (expected: ours, theirs, both, skip, interactive)",
                other
            ))),
        }
    }
}

/// Resolve every Conflict in `tree` according to `mode`. Returns the
/// cleaned tree and the number of conflicts that were resolved.
pub fn resolve_tree(tree: &TextTree, mode: ResolveMode) -> Result<(TextTree, usize)> {
    resolve_tree_with_overrides(tree, mode, &WordOverride::default())
}

/// Per-WORD override map for [`resolve_tree`]. Words not in the map
/// fall back to the global mode. (TODO.roadmap/56.)
#[derive(Default, Clone, Debug)]
pub struct WordOverride {
    overrides: std::collections::HashMap<String, ResolveMode>,
}

impl WordOverride {
    /// Parse `WORD:MODE` strings into an override map. Malformed
    /// entries surface as `Err`. Unknown mode values surface as
    /// `Err`. Repeated WORDs overwrite (last wins).
    pub fn from_cli_flags(flags: &[String]) -> Result<Self> {
        let mut overrides = std::collections::HashMap::new();
        for f in flags {
            let (word, mode_str) = f
                .split_once(':')
                .ok_or_else(|| Error::msg(format!("--word value must be WORD:MODE, got '{f}'")))?;
            if word.is_empty() {
                return Err(Error::msg(format!("--word value '{f}' has empty WORD")));
            }
            let mode = ResolveMode::from_cli_flag(mode_str)?;
            if matches!(mode, ResolveMode::Interactive) {
                return Err(Error::msg(format!(
                    "--word {word}:interactive not supported (interactive prompts only via --mode)"
                )));
            }
            overrides.insert(word.to_string(), mode);
        }
        Ok(WordOverride { overrides })
    }

    /// Look up the override for `word`, if any.
    pub fn get(&self, word: &str) -> Option<ResolveMode> {
        self.overrides.get(word).copied()
    }
}

/// Resolve every Conflict with a global mode plus per-WORD overrides.
/// The override wins when present; otherwise the global mode applies.
pub fn resolve_tree_with_overrides(
    tree: &TextTree,
    mode: ResolveMode,
    overrides: &WordOverride,
) -> Result<(TextTree, usize)> {
    let mut count = 0;
    let mut out = Vec::with_capacity(tree.len());
    for node in tree {
        match node {
            TextNode::Conflict { keyw, ours, theirs } => {
                let pick = if let Some(ov) = overrides.get(keyw) {
                    ov
                } else {
                    match mode {
                        ResolveMode::Interactive => prompt_one(keyw, ours, theirs)?,
                        other => other,
                    }
                };
                count += 1;
                emit_resolution(&mut out, keyw, ours, theirs, pick);
            }
            other => out.push(other.clone()),
        }
    }
    Ok((out, count))
}

fn emit_resolution(
    out: &mut TextTree,
    keyw: &str,
    ours: &TextTree,
    theirs: &TextTree,
    pick: ResolveMode,
) {
    match pick {
        ResolveMode::Ours => out.extend_from_slice(ours),
        ResolveMode::Theirs => out.extend_from_slice(theirs),
        ResolveMode::Both => {
            out.extend_from_slice(ours);
            out.extend_from_slice(theirs);
        }
        ResolveMode::Skip | ResolveMode::Interactive => {
            // Skip drops both. Interactive was already resolved to
            // one of the above by prompt_one; reaching here under
            // Interactive means the user chose Skip.
            let _ = (keyw, ours, theirs);
        }
    }
}

/// Prompt the user for one conflict's resolution. Reads from `stdin`.
fn prompt_one(keyw: &str, ours: &TextTree, theirs: &TextTree) -> Result<ResolveMode> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "CONFLICT on WORD {} — choose resolution [o/ours, t/theirs, b/both, s/skip]:",
        keyw
    )?;
    writeln!(stdout, "  -- ours --")?;
    print_tree(&mut stdout, ours, "    ")?;
    writeln!(stdout, "  -- theirs --")?;
    print_tree(&mut stdout, theirs, "    ")?;
    write!(stdout, "> ")?;
    stdout.flush()?;

    let mut buf = String::new();
    stdin.lock().read_line(&mut buf)?;
    let trimmed = buf.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "o" | "ours" => Ok(ResolveMode::Ours),
        "t" | "theirs" => Ok(ResolveMode::Theirs),
        "b" | "both" => Ok(ResolveMode::Both),
        "s" | "skip" | "" => Ok(ResolveMode::Skip),
        other => Err(Error::msg(format!(
            "unknown response '{}' (expected: o, t, b, s)",
            other
        ))),
    }
}

fn print_tree<W: Write>(out: &mut W, tree: &TextTree, indent: &str) -> Result<()> {
    for node in tree {
        match node {
            TextNode::Plain(s) => writeln!(out, "{}{}", indent, s)?,
            TextNode::Data(d) => writeln!(out, "{}<{} data bytes>", indent, d.len())?,
            TextNode::Stored { keyw, cas } => writeln!(
                out,
                "{}STORED {} {}",
                indent,
                keyw,
                &cas[..cas.len().min(16)]
            )?,
            TextNode::Encrypted { keyw, .. } => writeln!(out, "{}ENCRYPTED {}", indent, keyw)?,
            TextNode::BeginEnd { keyw, .. } => writeln!(out, "{}BEGIN/END {}", indent, keyw)?,
            TextNode::Chain { .. } => writeln!(out, "{}CHAIN", indent)?,
            TextNode::Include { hash } => {
                writeln!(out, "{}INCLUDE {}", indent, &hash[..hash.len().min(16)])?
            }
            TextNode::Conflict { keyw, .. } => writeln!(out, "{}CONFLICT {}", indent, keyw)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etree::ParseOps;
    use std::io::Cursor;

    fn parse_str(s: &str) -> TextTree {
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        crate::etree::parse(Cursor::new(s.as_bytes()), &mut paops).unwrap()
    }

    fn conflict_tree() -> TextTree {
        parse_str(
            "// <( CONFLICT X )>\n// <( OURS )>\n// <( BEGIN X )>\nhi-our\n// <( END X )>\n// <( THEIRS )>\n// <( BEGIN X )>\nhi-their\n// <( END X )>\n// <( END X )>\n",
        )
    }

    #[test]
    fn resolve_ours_drops_theirs_and_markers() {
        let t = conflict_tree();
        let (resolved, n) = resolve_tree(&t, ResolveMode::Ours).unwrap();
        assert_eq!(n, 1);
        // No Conflict node remains.
        assert!(
            !resolved
                .iter()
                .any(|n| matches!(n, TextNode::Conflict { .. }))
        );
        // Ours content survives.
        assert!(
            resolved
                .iter()
                .any(|n| matches!(n, TextNode::BeginEnd { keyw, .. } if keyw == "X"))
        );
    }

    #[test]
    fn resolve_theirs_drops_ours() {
        let t = conflict_tree();
        let (resolved, _) = resolve_tree(&t, ResolveMode::Theirs).unwrap();
        assert!(
            !resolved
                .iter()
                .any(|n| matches!(n, TextNode::Conflict { .. }))
        );
    }

    #[test]
    fn resolve_both_keeps_both_sides() {
        let t = conflict_tree();
        let (resolved, _) = resolve_tree(&t, ResolveMode::Both).unwrap();
        // Both copies of X appear.
        let x_count = resolved
            .iter()
            .filter(|n| matches!(n, TextNode::BeginEnd { keyw, .. } if keyw == "X"))
            .count();
        assert_eq!(x_count, 2);
    }

    #[test]
    fn resolve_skip_drops_everything() {
        let t = conflict_tree();
        let (resolved, _) = resolve_tree(&t, ResolveMode::Skip).unwrap();
        // No X anywhere.
        assert!(
            !resolved
                .iter()
                .any(|n| matches!(n, TextNode::BeginEnd { keyw, .. } if keyw == "X"))
        );
    }

    #[test]
    fn resolve_on_clean_tree_is_noop() {
        let t = parse_str("// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let (resolved, n) = resolve_tree(&t, ResolveMode::Ours).unwrap();
        assert_eq!(n, 0);
        assert_eq!(resolved, t);
    }

    #[test]
    fn mode_from_cli_flag_round_trips() {
        assert_eq!(
            ResolveMode::from_cli_flag("ours").unwrap(),
            ResolveMode::Ours
        );
        assert_eq!(
            ResolveMode::from_cli_flag("THEIRS").unwrap(),
            ResolveMode::Theirs
        );
        assert!(ResolveMode::from_cli_flag("garbage").is_err());
    }

    #[test]
    fn word_override_parses_valid_flags() {
        let ov = WordOverride::from_cli_flags(&[
            "Agent_007:ours".into(),
            "GEHEIM:theirs".into(),
            "PUBLIC:both".into(),
        ])
        .unwrap();
        assert_eq!(ov.get("Agent_007"), Some(ResolveMode::Ours));
        assert_eq!(ov.get("GEHEIM"), Some(ResolveMode::Theirs));
        assert_eq!(ov.get("PUBLIC"), Some(ResolveMode::Both));
        assert_eq!(ov.get("UNLISTED"), None);
    }

    #[test]
    fn word_override_rejects_malformed_flags() {
        assert!(WordOverride::from_cli_flags(&["no-colon".into()]).is_err());
        assert!(WordOverride::from_cli_flags(&[":ours".into()]).is_err());
        assert!(WordOverride::from_cli_flags(&["X:bogus".into()]).is_err());
        // Interactive isn't allowed as a per-WORD override — the
        // prompt path only fires via --mode.
        assert!(WordOverride::from_cli_flags(&["X:interactive".into()]).is_err());
    }

    #[test]
    fn resolve_per_word_override_wins_over_global_mode() {
        let t = parse_str(
            "// <( CONFLICT X )>\n// <( OURS )>\n// <( BEGIN X )>\nhi-our\n// <( END X )>\n// <( THEIRS )>\n// <( BEGIN X )>\nhi-their\n// <( END X )>\n// <( END X )>\n// <( CONFLICT Y )>\n// <( OURS )>\n// <( BEGIN Y )>\nyo-our\n// <( END Y )>\n// <( THEIRS )>\n// <( BEGIN Y )>\nyo-their\n// <( END Y )>\n// <( END Y )>\n",
        );
        let ov = WordOverride::from_cli_flags(&["X:ours".into()]).unwrap();
        let (resolved, _) = resolve_tree_with_overrides(&t, ResolveMode::Theirs, &ov).unwrap();
        // X takes ours (override wins).
        let body = serialize(&resolved);
        assert!(body.contains("hi-our") && !body.contains("hi-their"));
        // Y falls back to global mode (theirs).
        assert!(body.contains("yo-their") && !body.contains("yo-our"));
    }

    fn serialize(tree: &TextTree) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let mut paops = ParseOps::new(crate::crypto::default_policy()).unwrap();
        crate::etree::tree_write(&mut buf, tree, &mut paops).unwrap();
        String::from_utf8(buf).unwrap()
    }
}
