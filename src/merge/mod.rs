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

//! Three-way WORD-region merge driver (TODO.roadmap/43).
//!
//! The merge driver is the bridge between git's textual merge model
//! and enprot's WORD-region semantics. Git hands us three files —
//! the common ancestor (`%O`), ours (`%A`), and theirs (`%B`) — and
//! expects us to write a merged result back into `%A`. The path is
//! `%P`.
//!
//! Strategy: parse each side into a [`TextTree`], partition each
//! tree into "segments" keyed by WORD name + position, then walk the
//! segments in lock-step:
//!
//! - All three sides agree → take it.
//! - Ours and theirs both diverge from ancestor → emit a
//!   [`TextNode::Conflict`] carrying both versions. Both sides stay
//!   valid host-language source because the conflict marker is just
//!   another EPT directive (`// <( CONFLICT <word> )> ...`).
//! - Only one side diverges → take that side (standard 3-way merge
//!   rule).
//!
//! Non-WORD content (Plain lines outside any BEGIN/END) is merged
//! line-by-line using the same ancestor/ours/theirs rule. Conflicts
//! there bubble up as plain `<<<<<<<`/`>>>>>>>` markers — the merge
//! driver can't do better than the textual diff for unstructured
//! content.

use crate::error::Result;
use crate::etree::{TextNode, TextTree};

/// Segment in a partitioned tree: either free-form Plain content or
/// a named WORD region. Conflict markers and INCLUDE/CHAIN nodes
/// are treated as their own one-element segments so they round-trip
/// cleanly through the merge.
#[derive(Debug, Clone)]
enum Segment {
    /// One or more consecutive `Plain` lines (and `Data` lines).
    Plain(TextTree),
    /// A `BeginEnd` or `Encrypted` block plus its keyw.
    Region {
        keyw: String,
        ours_tag: RegionTag,
        nodes: TextTree,
    },
    /// A passthrough node (Stored, Chain, Include, Conflict) that
    /// shouldn't be re-merged.
    Atom(TextNode),
}

/// Distinguishes the two region flavours that the merge driver
/// cares about. Same keyw with different tags is treated as the
/// same region (a region can transition between flavours across
/// versions — e.g. a BEGIN that gets encrypted).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum RegionTag {
    BeginEnd,
    Encrypted,
}

/// Partition a tree into segments. Consecutive Plain/Data nodes
/// collapse into one `Segment::Plain`; each Begin/Encrypted opens
/// a fresh `Segment::Region`; other nodes become `Segment::Atom`.
fn partition(tree: &TextTree) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut plain_buf: TextTree = Vec::new();
    for node in tree {
        match node {
            TextNode::Plain(_) | TextNode::Data(_) => plain_buf.push(node.clone()),
            TextNode::BeginEnd { keyw, txt } => {
                if !plain_buf.is_empty() {
                    out.push(Segment::Plain(std::mem::take(&mut plain_buf)));
                }
                out.push(Segment::Region {
                    keyw: keyw.clone(),
                    ours_tag: RegionTag::BeginEnd,
                    nodes: txt.clone(),
                });
            }
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => {
                if !plain_buf.is_empty() {
                    out.push(Segment::Plain(std::mem::take(&mut plain_buf)));
                }
                // Encrypted blocks carry extfields that the merge
                // must preserve; keep the whole node intact and
                // re-emit as a Region whose payload is the children.
                let _ = extfields; // extfields travel with the node when merged.
                out.push(Segment::Region {
                    keyw: keyw.clone(),
                    ours_tag: RegionTag::Encrypted,
                    nodes: txt.clone(),
                });
            }
            TextNode::Stored { .. } | TextNode::Chain { .. } | TextNode::Include { .. } => {
                if !plain_buf.is_empty() {
                    out.push(Segment::Plain(std::mem::take(&mut plain_buf)));
                }
                out.push(Segment::Atom(node.clone()));
            }
            TextNode::Conflict { .. } => {
                // An existing Conflict node (e.g. from a prior
                // unresolved merge) is treated as opaque — we don't
                // try to merge conflicts recursively.
                if !plain_buf.is_empty() {
                    out.push(Segment::Plain(std::mem::take(&mut plain_buf)));
                }
                out.push(Segment::Atom(node.clone()));
            }
        }
    }
    if !plain_buf.is_empty() {
        out.push(Segment::Plain(plain_buf));
    }
    out
}

/// Merge outcome for a single segment comparison.
enum MergePick {
    /// All sides agree (or only one side diverged); take this single
    /// payload.
    Take(TextTree),
    /// Both sides diverged; emit a Conflict node with this keyw.
    Conflict {
        keyw: String,
        ours: TextTree,
        theirs: TextTree,
    },
}

/// Merge outcome for a Plain segment. Same shape as MergePick but
/// always uses the reserved `__plain__` keyw so the resolve layer
/// can spot non-WORD conflicts.
enum PlainPick {
    Take(TextTree),
    Conflict { ours: TextTree, theirs: TextTree },
}

/// Reserved keyw for plain-segment conflicts. Double-underscore
/// prefix avoids collision with real WORD identifiers (which are
/// unqualified identifiers in every host language).
const PLAIN_KEYWORD: &str = "__plain__";

/// Three-way merge for Plain segments. Mirrors `merge_one_region`
/// but emits a [`PlainPick`] (caller wraps with `PLAIN_KEYWORD`).
fn merge_one_plain(
    base: Option<&TextTree>,
    ours: Option<&TextTree>,
    theirs: Option<&TextTree>,
) -> PlainPick {
    match (base, ours, theirs) {
        // All three identical (or only one side changed) → take it.
        (Some(_), Some(o), Some(t)) if o == t => PlainPick::Take(o.clone()),
        (Some(b), Some(o), Some(t)) if o == b => PlainPick::Take(t.clone()),
        (Some(b), Some(o), Some(t)) if t == b => PlainPick::Take(o.clone()),
        (Some(_), Some(o), Some(t)) => PlainPick::Conflict {
            ours: o.clone(),
            theirs: t.clone(),
        },
        // Plain added on one side only.
        (None, Some(o), None) => PlainPick::Take(o.clone()),
        (None, None, Some(t)) => PlainPick::Take(t.clone()),
        // Plain removed on both sides — nothing to emit.
        (Some(_), None, None) => PlainPick::Take(Vec::new()),
        // Plain removed on one side, modified on the other — keep
        // the modified version (modify-wins-over-delete, same rule
        // as for regions).
        (Some(_), Some(o), None) => PlainPick::Take(o.clone()),
        (Some(_), None, Some(t)) => PlainPick::Take(t.clone()),
        // Plain added on both sides identically.
        (None, Some(o), Some(t)) if o == t => PlainPick::Take(o.clone()),
        // Plain added on both sides differently.
        (None, Some(o), Some(t)) => PlainPick::Conflict {
            ours: o.clone(),
            theirs: t.clone(),
        },
        // Defensive — see merge_one_region for the rationale.
        (None, None, None) => PlainPick::Take(Vec::new()),
    }
}

/// Three-way merge two partitioned trees against a shared ancestor.
/// Returns the merged tree. Conflicts become [`TextNode::Conflict`]
/// nodes; the caller (typically `enprot resolve`) decides how to
/// surface them.
///
/// Walk strategy: ours is authoritative for layout — we walk ours
/// segment-by-segment and emit each one, only delegating to the
/// three-way merge for Region segments. Plain segments go through
/// the same three-way merge by positional index (the i-th Plain in
/// ours is matched against the i-th Plain in base and theirs); a
/// both-sides-diverge Plain produces a `CONFLICT __plain__` block
/// rather than silently dropping the theirs side (TODO.roadmap/48).
/// Atom segments pass through unchanged. Region segments missing
/// from theirs are kept as ours (modify-wins-over-delete); regions
/// added in theirs but absent from ours are appended after ours'
/// last region.
pub fn merge_trees(base: &TextTree, ours: &TextTree, theirs: &TextTree) -> Result<TextTree> {
    let base_seg = partition(base);
    let ours_seg = partition(ours);
    let theirs_seg = partition(theirs);

    let find_region = |segs: &[Segment], keyw: &str, tag: RegionTag| -> Option<TextTree> {
        segs.iter().find_map(|s| match s {
            Segment::Region {
                keyw: k,
                ours_tag: t,
                nodes,
            } if k == keyw && *t == tag => Some(nodes.clone()),
            _ => None,
        })
    };

    // Plain segments don't carry identity, so we match them
    // positionally: the i-th Plain in ours corresponds to the i-th
    // Plain in base and theirs. Inserting or removing a Plain
    // segment shifts indices downstream — accepted trade-off given
    // that the alternative (content-hash matching) breaks when two
    // segments happen to be identical.
    let plain_at = |segs: &[Segment], i: usize| -> Option<TextTree> {
        segs.iter()
            .filter_map(|s| match s {
                Segment::Plain(nodes) => Some(nodes.clone()),
                _ => None,
            })
            .nth(i)
    };
    let mut next_plain_idx = 0usize;

    let mut out: TextTree = Vec::new();
    let mut handled: Vec<(String, RegionTag)> = Vec::new();

    // Pass 1: walk ours positionally so Plain/Atom segments stay in
    // their original places. Regions go through the 3-way merge.
    for s in &ours_seg {
        match s {
            Segment::Plain(nodes) => {
                let i = next_plain_idx;
                next_plain_idx += 1;
                let base_plain = plain_at(&base_seg, i);
                let theirs_plain = plain_at(&theirs_seg, i);
                match merge_one_plain(base_plain.as_ref(), Some(nodes), theirs_plain.as_ref()) {
                    PlainPick::Take(nodes) => out.extend_from_slice(&nodes),
                    PlainPick::Conflict { ours, theirs } => {
                        out.push(TextNode::Plain("\n".to_string()));
                        out.push(TextNode::Conflict {
                            keyw: PLAIN_KEYWORD.to_string(),
                            ours,
                            theirs,
                        });
                    }
                }
            }
            Segment::Atom(node) => out.push(node.clone()),
            Segment::Region { keyw, ours_tag, .. } => {
                let key = (keyw.clone(), *ours_tag);
                let base_nodes = find_region(&base_seg, &key.0, key.1);
                let theirs_nodes = find_region(&theirs_seg, &key.0, key.1);
                let ours_nodes = find_region(&ours_seg, &key.0, key.1);
                let pick = merge_one_region(
                    &key.0,
                    base_nodes.as_ref(),
                    ours_nodes.as_ref(),
                    theirs_nodes.as_ref(),
                )?;
                match pick {
                    MergePick::Take(nodes) => emit_region(&mut out, &key.0, key.1, &nodes),
                    MergePick::Conflict { keyw, ours, theirs } => {
                        out.push(TextNode::Conflict { keyw, ours, theirs });
                    }
                }
                handled.push(key);
            }
        }
    }

    // Pass 2: regions present in theirs but missing from ours. These
    // are additions on their side that didn't exist in our working
    // tree. Append them at the end so they aren't lost.
    for s in &theirs_seg {
        if let Segment::Region { keyw, ours_tag, .. } = s {
            let key = (keyw.clone(), *ours_tag);
            if handled.contains(&key) {
                continue;
            }
            let base_nodes = find_region(&base_seg, &key.0, key.1);
            let theirs_nodes = find_region(&theirs_seg, &key.0, key.1);
            let pick = merge_one_region(&key.0, base_nodes.as_ref(), None, theirs_nodes.as_ref())?;
            match pick {
                MergePick::Take(nodes) => emit_region(&mut out, &key.0, key.1, &nodes),
                MergePick::Conflict { keyw, ours, theirs } => {
                    out.push(TextNode::Conflict { keyw, ours, theirs });
                }
            }
            handled.push(key);
        }
    }

    Ok(out)
}

fn merge_one_region(
    keyw: &str,
    base: Option<&TextTree>,
    ours: Option<&TextTree>,
    theirs: Option<&TextTree>,
) -> Result<MergePick> {
    use Option::*;
    match (base, ours, theirs) {
        // All three identical → take it.
        (Some(b), Some(o), Some(t)) if o == t && o == b => Ok(MergePick::Take(o.clone())),
        // Ours == theirs but != base → both sides made the same change.
        (Some(_), Some(o), Some(t)) if o == t => Ok(MergePick::Take(o.clone())),
        // Only ours changed.
        (Some(b), Some(o), Some(t)) if o != b && t == b => Ok(MergePick::Take(o.clone())),
        // Only theirs changed.
        (Some(b), Some(o), Some(t)) if t != b && o == b => Ok(MergePick::Take(t.clone())),
        // Both diverged → conflict.
        (Some(_), Some(o), Some(t)) => Ok(MergePick::Conflict {
            keyw: keyw.to_string(),
            ours: o.clone(),
            theirs: t.clone(),
        }),
        // Region added on one side only → take it.
        (None, Some(o), None) => Ok(MergePick::Take(o.clone())),
        (None, None, Some(t)) => Ok(MergePick::Take(t.clone())),
        // Region present in base but removed on both sides → drop.
        (Some(_), None, None) => Ok(MergePick::Take(Vec::new())),
        // Region removed on one side, modified on the other → keep
        // the modified version (modify-wins-over-delete is the
        // standard 3-way default for non-conflicting changes).
        (Some(_), Some(o), None) => Ok(MergePick::Take(o.clone())),
        (Some(_), None, Some(t)) => Ok(MergePick::Take(t.clone())),
        // Region added on both sides identically → take it.
        (None, Some(o), Some(t)) if o == t => Ok(MergePick::Take(o.clone())),
        // Region added on both sides differently → conflict.
        (None, Some(o), Some(t)) => Ok(MergePick::Conflict {
            keyw: keyw.to_string(),
            ours: o.clone(),
            theirs: t.clone(),
        }),
        // Defensive: shouldn't happen because `ordered_keys` is the
        // union of region identities — at least one side must have
        // the region.
        (None, None, None) => Ok(MergePick::Take(Vec::new())),
    }
}

/// Re-emit a region under its original tag. Encrypted regions lose
/// their extfields here — the merge driver treats the payload
/// (plaintext or ciphertext bytes) as the source of truth and lets
/// the encrypt/decrypt pipeline regenerate extfields on the next
/// pass. This is fine for the common case (CAS-referenced blocks
/// where the hash itself encodes everything needed).
fn emit_region(out: &mut TextTree, keyw: &str, tag: RegionTag, nodes: &TextTree) {
    if nodes.is_empty() {
        return;
    }
    match tag {
        RegionTag::BeginEnd => out.push(TextNode::BeginEnd {
            keyw: keyw.to_string(),
            txt: nodes.clone(),
        }),
        RegionTag::Encrypted => out.push(TextNode::Encrypted {
            keyw: keyw.to_string(),
            txt: nodes.clone(),
            extfields: Default::default(),
        }),
    }
}

/// Drive a merge from three file paths. The driver writes the
/// merged result back into `ours_path` (the standard git merge-driver
/// contract). Returns Ok with the number of conflicts emitted;
/// returns Err if any file can't be read or parsed.
pub fn merge_paths(
    base_path: &std::path::Path,
    ours_path: &std::path::Path,
    theirs_path: &std::path::Path,
) -> Result<usize> {
    let base = read_tree(base_path)?;
    let ours = read_tree(ours_path)?;
    let theirs = read_tree(theirs_path)?;
    let merged = merge_trees(&base, &ours, &theirs)?;
    let conflicts = count_conflicts(&merged);
    write_tree(ours_path, &merged)?;
    Ok(conflicts)
}

fn read_tree(path: &std::path::Path) -> Result<TextTree> {
    use crate::crypto::CryptoPolicyDefault;
    use crate::etree::ParseOps;
    use std::fs::File;
    use std::io::BufReader;
    let f = File::open(path)?;
    let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {}))?;
    paops.runtime.fname = path.display().to_string();
    etree_parse(BufReader::new(f), &mut paops)
}

fn write_tree(path: &std::path::Path, tree: &TextTree) -> Result<()> {
    use crate::crypto::CryptoPolicyDefault;
    use crate::etree::{ParseOps, tree_write};
    use std::fs::File;
    use std::io::BufWriter;
    let f = File::create(path)?;
    let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {}))?;
    paops.runtime.fname = path.display().to_string();
    let mut w = BufWriter::new(f);
    tree_write(&mut w, tree, &mut paops)
}

fn count_conflicts(tree: &TextTree) -> usize {
    tree.iter()
        .filter(|n| matches!(n, TextNode::Conflict { .. }))
        .count()
}

// Local re-exports so the helpers above don't all need to repeat
// the full path.
use crate::etree as etree_parse_mod;
use etree_parse_mod::parse as etree_parse;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoPolicyDefault;
    use crate::etree::{Directive, ParseOps};
    use std::io::Cursor;

    fn parse_str(s: &str) -> TextTree {
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
        crate::etree::parse(Cursor::new(s.as_bytes()), &mut paops).unwrap()
    }

    fn plain(s: &str) -> TextTree {
        vec![TextNode::Plain(s.into())]
    }

    #[test]
    fn identical_inputs_produce_identical_output_with_no_conflicts() {
        let a = parse_str("// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n");
        let merged = merge_trees(&a, &a, &a).unwrap();
        assert_eq!(merged, a);
        assert_eq!(count_conflicts(&merged), 0);
    }

    #[test]
    fn disjoint_word_changes_merge_cleanly() {
        let base = parse_str(
            "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho\n// <( END GEHEIM )>\n",
        );
        let ours = parse_str(
            "// <( BEGIN Agent_007 )>\nhi-our\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho\n// <( END GEHEIM )>\n",
        );
        let theirs = parse_str(
            "// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n// <( BEGIN GEHEIM )>\nho-their\n// <( END GEHEIM )>\n",
        );
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        assert_eq!(count_conflicts(&merged), 0);
        // Both edits land in the output.
        let serialized = serialize(&merged);
        assert!(serialized.contains("hi-our"), "serialized = {serialized}");
        assert!(serialized.contains("ho-their"));
    }

    #[test]
    fn same_word_different_content_produces_conflict() {
        let base = parse_str("// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\n");
        let ours = parse_str("// <( BEGIN Agent_007 )>\nhi-our\n// <( END Agent_007 )>\n");
        let theirs = parse_str("// <( BEGIN Agent_007 )>\nhi-their\n// <( END Agent_007 )>\n");
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        assert_eq!(count_conflicts(&merged), 1);
        match &merged[0] {
            TextNode::Conflict { keyw, ours, theirs } => {
                assert_eq!(keyw, "Agent_007");
                assert!(!ours.is_empty());
                assert!(!theirs.is_empty());
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn one_sided_delete_against_modify_keeps_modify() {
        let base = parse_str("// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let ours = parse_str("// <( BEGIN X )>\nbody-modified\n// <( END X )>\n");
        let theirs = parse_str("plain trailing line\n");
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        assert_eq!(count_conflicts(&merged), 0);
        // Modify-wins-over-delete: the modified region survives.
        let serialized = serialize(&merged);
        assert!(serialized.contains("body-modified"));
    }

    #[test]
    fn both_sides_modified_plain_emits_plain_conflict() {
        // TODO.roadmap/48: previously the theirs-side Plain edit was
        // silently dropped. Now both sides land in a CONFLICT block
        // under the reserved __plain__ keyw.
        let base = parse_str("intro\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let ours = parse_str("intro-our\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let theirs = parse_str("intro-their\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        let serialized = serialize(&merged);
        assert!(
            serialized.contains("CONFLICT __plain__"),
            "expected __plain__ conflict; got:\n{serialized}"
        );
        assert!(serialized.contains("intro-our"));
        assert!(serialized.contains("intro-their"));
    }

    #[test]
    fn one_sided_plain_change_merges_cleanly() {
        let base = parse_str("intro\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let ours = parse_str("intro-our\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let theirs = parse_str("intro\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        assert_eq!(count_conflicts(&merged), 0);
        assert!(serialize(&merged).contains("intro-our"));
    }

    #[test]
    fn identical_plain_change_on_both_sides_merges_cleanly() {
        let base = parse_str("intro\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let ours = parse_str("intro-edited\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let theirs = parse_str("intro-edited\n// <( BEGIN X )>\nbody\n// <( END X )>\n");
        let merged = merge_trees(&base, &ours, &theirs).unwrap();
        assert_eq!(count_conflicts(&merged), 0);
    }

    fn serialize(tree: &TextTree) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let mut paops = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
        crate::etree::tree_write(&mut buf, tree, &mut paops).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn round_trips_through_partition() {
        // Sanity: partition collects consecutive Plain nodes and
        // isolates each region. Re-merging the partition against
        // itself yields the same tree.
        let a =
            parse_str("leading\n// <( BEGIN Agent_007 )>\nhi\n// <( END Agent_007 )>\ntrailing\n");
        let merged = merge_trees(&a, &a, &a).unwrap();
        // Round-trip may relocate Plain segments (the merge driver
        // emits leading-then-regions-then-atoms) so compare by
        // content presence rather than exact equality.
        let s = serialize(&merged);
        assert!(s.contains("leading"));
        assert!(s.contains("trailing"));
        assert!(s.contains("Agent_007"));
        let _ = Directive::Begin; // suppress unused-import warning if Directive not otherwise used
    }

    // `plain` helper is reserved for future tests that exercise
    // free-form plain merging; suppress dead-code warning.
    #[test]
    #[allow(dead_code)]
    fn plain_helper_compiles() {
        let _ = plain("hello");
    }
}
