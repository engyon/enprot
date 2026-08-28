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

//! The single deep traversal over [`TextTree`] (architecture review
//! 2026-08-27, candidate 2).
//!
//! Before this module existed, eleven call sites hand-rolled the same
//! recursive descent — descend into `BeginEnd`/`Encrypted` children,
//! match the node kind, act, recurse. The knowledge of which node
//! kinds have children lived in eleven places. [`visit`] concentrates
//! it here; consumers supply only their per-kind logic.
//!
//! ## Interface
//!
//! - [`visit`] — read-only walk, pre-order (parents before
//!   children), depth-first. The visitor returns `Control` to
//!   continue or prune a subtree.
//! - [`visit_depth`] — same walk carrying the node's nesting depth
//!   (0 at top level), for the renderer/projection family (round 8:
//!   the second depth-tracking consumer made this seam real).
//! - [`visit_mut`] — same shape for rewriting walks (the
//!   migrate-keys/rotate family): the visitor may replace a node's
//!   payload; children are descended after the parent is visited.
//!
//! The traversal contract (ordering, nesting, which kinds descend) is
//! tested once, here — visitors test only their match logic.

use super::{TextNode, TextTree};

/// What a visitor wants after seeing one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Descend into this node's children (if any), then continue
    /// with its siblings.
    Continue,
    /// Skip this node's children entirely, but keep walking
    /// siblings.
    Prune,
}

/// Read-only pre-order visit. `f` sees every node in the tree,
/// parents before children.
pub fn visit(tree: &TextTree, f: &mut dyn FnMut(&TextNode) -> Control) {
    visit_depth(tree, &mut |node, _| f(node));
}

/// Depth-aware pre-order visit: like [`visit`], but `f` also receives
/// the node's nesting depth (0 at the top level, one more per
/// descended level). Renderers key indentation and DTO `depth` fields
/// off this argument instead of hand-rolling recursion.
pub fn visit_depth(tree: &TextTree, f: &mut dyn FnMut(&TextNode, usize) -> Control) {
    visit_depth_at(tree, 0, f);
}

fn visit_depth_at(tree: &TextTree, depth: usize, f: &mut dyn FnMut(&TextNode, usize) -> Control) {
    for node in tree {
        match f(node, depth) {
            Control::Continue => match node {
                TextNode::BeginEnd { txt, .. } | TextNode::Encrypted { txt, .. } => {
                    visit_depth_at(txt, depth + 1, f);
                }
                _ => {}
            },
            Control::Prune => {}
        }
    }
}

/// Rewriting pre-order visit over a mutable tree. `f` sees each node
/// mutably and returns [`Control`]; `Continue` descends into the
/// node's (possibly just-rewritten) children.
pub fn visit_mut(tree: &mut TextTree, f: &mut dyn FnMut(&mut TextNode) -> Control) {
    for node in tree.iter_mut() {
        match f(node) {
            Control::Continue => match node {
                TextNode::BeginEnd { txt, .. } | TextNode::Encrypted { txt, .. } => {
                    visit_mut(txt, f);
                }
                _ => {}
            },
            Control::Prune => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> TextTree {
        let policy = crate::crypto::default_policy();
        let mut paops = crate::etree::ParseOps::new(policy).unwrap();
        crate::etree::parse(std::io::Cursor::new(s), &mut paops).unwrap()
    }

    fn flat() -> TextTree {
        parse("plain\n// <( BEGIN W )>\ninner\n// <( END W )>\nplain2\n")
    }

    #[test]
    fn pre_order_sees_parents_before_children() {
        let tree = flat();
        let mut order: Vec<&str> = Vec::new();
        visit(&tree, &mut |node| {
            match node {
                TextNode::Plain(_) => order.push("plain"),
                TextNode::BeginEnd { .. } => order.push("begin-end"),
                _ => order.push("other"),
            }
            Control::Continue
        });
        // The first Plain precedes the BeginEnd; the inner Plain
        // (the child) comes after its parent.
        assert_eq!(order, vec!["plain", "begin-end", "plain", "plain"]);
    }

    #[test]
    fn prune_skips_children_but_not_siblings() {
        let tree = flat();
        let mut seen: Vec<&str> = Vec::new();
        visit(&tree, &mut |node| {
            match node {
                TextNode::Plain(_) => seen.push("plain"),
                TextNode::BeginEnd { .. } => {
                    seen.push("begin-end");
                    return Control::Prune; // skip the inner Plain
                }
                _ => seen.push("other"),
            }
            Control::Continue
        });
        // The inner plain (child of the pruned block) is absent; the
        // trailing plain2 sibling is present.
        assert_eq!(seen, vec!["plain", "begin-end", "plain"]);
    }

    #[test]
    fn descends_into_encrypted_children() {
        let tree = parse(
            "// <( ENCRYPTED W pbkdf:$argon2$m=1,p=1,t=1$AAAA )>\n// <( DATA AAAA )>\n// <( END W )>\n",
        );
        let mut saw_encrypted = false;
        let mut saw_data = false;
        visit(&tree, &mut |node| {
            match node {
                TextNode::Encrypted { .. } => saw_encrypted = true,
                TextNode::Data(_) => saw_data = true,
                _ => {}
            }
            Control::Continue
        });
        assert!(
            saw_encrypted && saw_data,
            "Data child of Encrypted must be visited"
        );
    }

    #[test]
    fn visit_mut_rewrites_in_place() {
        let mut tree = flat();
        visit_mut(&mut tree, &mut |node| {
            if let TextNode::Plain(p) = node {
                p.push('!');
            }
            Control::Continue
        });
        let mut out = Vec::new();
        let policy = crate::crypto::default_policy();
        let mut paops = crate::etree::ParseOps::new(policy).unwrap();
        crate::etree::tree_write(&mut out, &tree, &mut paops).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("plain!\n") && s.contains("inner!"), "{s}");
    }

    #[test]
    fn visit_mut_prune_preserves_subtree() {
        let mut tree = flat();
        visit_mut(&mut tree, &mut |node| {
            if let TextNode::BeginEnd { txt, .. } = node {
                txt.clear(); // rewriting children away entirely
                return Control::Prune;
            }
            Control::Continue
        });
        let mut saw_inner = false;
        visit(&tree, &mut |n| {
            if let TextNode::Plain(p) = n
                && p.contains("inner")
            {
                saw_inner = true;
            }
            Control::Continue
        });
        assert!(!saw_inner, "cleared children must not reappear");
    }

    #[test]
    fn visit_depth_numbers_nesting() {
        let tree = flat();
        let mut seen: Vec<(&str, usize)> = Vec::new();
        visit_depth(&tree, &mut |node, d| {
            match node {
                TextNode::Plain(_) => seen.push(("plain", d)),
                TextNode::BeginEnd { .. } => seen.push(("begin-end", d)),
                _ => seen.push(("other", d)),
            }
            Control::Continue
        });
        // Top level is depth 0; the inner Plain sits at depth 1.
        assert_eq!(
            seen,
            vec![("plain", 0), ("begin-end", 0), ("plain", 1), ("plain", 0)]
        );
    }

    #[test]
    fn visit_depth_prune_hides_child_depths() {
        let tree = flat();
        let mut depths = Vec::new();
        visit_depth(&tree, &mut |node, d| {
            depths.push(d);
            match node {
                TextNode::BeginEnd { .. } => Control::Prune,
                _ => Control::Continue,
            }
        });
        // No depth-1 row survives the pruned region; the trailing
        // sibling is back at depth 0.
        assert_eq!(depths, vec![0, 0, 0]);
    }

    #[test]
    fn visit_depth_descends_into_encrypted() {
        let tree = parse(
            "// <( ENCRYPTED W pbkdf:$argon2$m=1,p=1,t=1$AAAA )>\n// <( DATA AAAA )>\n// <( END W )>\n",
        );
        let mut saw = Vec::new();
        visit_depth(&tree, &mut |node, d| {
            if let TextNode::Data(_) = node {
                saw.push(d);
            }
            Control::Continue
        });
        assert_eq!(saw, vec![1], "Data child must arrive at depth 1");
    }

    #[test]
    fn deeply_nested_trees_descend_fully() {
        // 3 levels: BEGIN > BEGIN > BEGIN > plain
        let input = "// <( BEGIN A )>\n// <( BEGIN B )>\n// <( BEGIN C )>\ndeep\n// <( END C )>\n// <( END B )>\n// <( END A )>\n";
        let tree = parse(input);
        let mut depth = 0usize;
        let mut max_depth = 0usize;
        visit(&tree, &mut |node| {
            if let TextNode::BeginEnd { .. } = node {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            Control::Continue
        });
        assert_eq!(max_depth, 3);
    }
}
