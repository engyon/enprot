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

//! Inverse of `parse`: emit EPT markup from a `TextTree`. IO errors
//! propagate (audit A8); a write failure no longer panics.

use std::io::Write;

use crate::error::Result;
use crate::etree::Directive;
use crate::etree::ParseOps;
use crate::etree::TextNode;
use crate::etree::TextTree;
use crate::utils;

const DATA_BYTES_PER_LINE: usize = 48;

pub fn tree_write<W: Write>(outw: &mut W, text: &TextTree, paops: &mut ParseOps) -> Result<()> {
    for elem in text {
        match elem {
            TextNode::Plain(line) => writeln!(outw, "{}", line)?,
            TextNode::BeginEnd { keyw, txt } => {
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Begin.keyword(),
                    keyw,
                    paops.separators.right
                )?;
                paops.runtime.level += 1;
                tree_write(outw, txt, paops)?;
                paops.runtime.level -= 1;
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::End.keyword(),
                    keyw,
                    paops.separators.right
                )?;
            }
            TextNode::Encrypted {
                keyw,
                txt,
                extfields,
            } => {
                write!(
                    outw,
                    "{} {} {}",
                    paops.separators.left,
                    Directive::Encrypted.keyword(),
                    keyw
                )?;
                // `first()` rather than indexing: parse guarantees the
                // Encrypted node has exactly one child, but a library
                // consumer can construct an empty tree — emit the
                // multiline form instead of panicking.
                if let Some(TextNode::Stored { keyw: _, cas }) = txt.first() {
                    write!(outw, " {}", cas)?;
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.separators.right)?;
                } else {
                    for (key, value) in extfields.iter() {
                        write!(outw, " {}:{}", key, value)?;
                    }
                    writeln!(outw, " {}", paops.separators.right)?;
                    paops.runtime.level += 1;
                    tree_write(outw, txt, paops)?;
                    paops.runtime.level -= 1;
                    writeln!(
                        outw,
                        "{} {} {} {}",
                        paops.separators.left,
                        Directive::End.keyword(),
                        keyw,
                        paops.separators.right
                    )?;
                }
            }
            TextNode::Stored { keyw, cas } => {
                writeln!(
                    outw,
                    "{} {} {} {} {}",
                    paops.separators.left,
                    Directive::Stored.keyword(),
                    keyw,
                    cas,
                    paops.separators.right
                )?;
            }
            TextNode::Data(data) => {
                for chunk in data.chunks(DATA_BYTES_PER_LINE) {
                    writeln!(
                        outw,
                        "{} {} {} {}",
                        paops.separators.left,
                        Directive::Data.keyword(),
                        utils::base64_encode(chunk)?,
                        paops.separators.right
                    )?;
                }
            }
            TextNode::Chain { extfields } => {
                // Single-line: CHAIN followed by space-separated key:value pairs.
                write!(
                    outw,
                    "{} {}",
                    paops.separators.left,
                    Directive::Chain.keyword()
                )?;
                for (key, value) in extfields.iter() {
                    write!(outw, " {}:{}", key, value)?;
                }
                writeln!(outw, " {}", paops.separators.right)?;
            }
            TextNode::Include { hash } => {
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Include.keyword(),
                    hash,
                    paops.separators.right
                )?;
            }
            TextNode::Conflict { keyw, ours, theirs } => {
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Conflict.keyword(),
                    keyw,
                    paops.separators.right
                )?;
                paops.runtime.level += 1;
                writeln!(
                    outw,
                    "{} {} {}",
                    paops.separators.left,
                    Directive::Ours.keyword(),
                    paops.separators.right
                )?;
                tree_write(outw, ours, paops)?;
                writeln!(
                    outw,
                    "{} {} {}",
                    paops.separators.left,
                    Directive::Theirs.keyword(),
                    paops.separators.right
                )?;
                tree_write(outw, theirs, paops)?;
                paops.runtime.level -= 1;
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::End.keyword(),
                    keyw,
                    paops.separators.right
                )?;
            }
            TextNode::Immutable {
                name,
                hashalg,
                hash,
                txt,
            } => {
                writeln!(
                    outw,
                    "{} {} {} {}={} {}",
                    paops.separators.left,
                    Directive::Immutable.keyword(),
                    name,
                    hashalg,
                    hash,
                    paops.separators.right
                )?;
                paops.runtime.level += 1;
                tree_write(outw, txt, paops)?;
                paops.runtime.level -= 1;
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Mutable.keyword(),
                    name,
                    paops.separators.right
                )?;
            }
            TextNode::Muted {
                name,
                hashalg,
                hash,
            } => {
                writeln!(
                    outw,
                    "{} {} {} {}={} {}",
                    paops.separators.left,
                    Directive::Muted.keyword(),
                    name,
                    hashalg,
                    hash,
                    paops.separators.right
                )?;
            }
            TextNode::Key {
                name,
                hashalg,
                hash,
            } => {
                writeln!(
                    outw,
                    "{} {} {} {}={} {}",
                    paops.separators.left,
                    Directive::Key.keyword(),
                    name,
                    hashalg,
                    hash,
                    paops.separators.right
                )?;
            }
            TextNode::Unkey { name } => {
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Unkey.keyword(),
                    name,
                    paops.separators.right
                )?;
            }
            TextNode::Cert {
                name,
                hashalg,
                hash,
            } => {
                writeln!(
                    outw,
                    "{} {} {} {}={} {}",
                    paops.separators.left,
                    Directive::Cert.keyword(),
                    name,
                    hashalg,
                    hash,
                    paops.separators.right
                )?;
            }
            TextNode::Uncert { name } => {
                writeln!(
                    outw,
                    "{} {} {} {}",
                    paops.separators.left,
                    Directive::Uncert.keyword(),
                    name,
                    paops.separators.right
                )?;
            }
        }
    }
    Ok(())
}

/// Wire-format spec for `tree_write` (TODO.complete/49).
///
/// Every `TextNode` variant has a golden serialization test that
/// constructs the model directly (no parsing) and asserts the exact
/// emitted markup. These are the only in-process writer tests — the
/// CLI integration tests spawn a subprocess, which coverage does not
/// attribute — so this module is the spec of record for the
/// unparser's wire format.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::etree::TextNode;
    use std::collections::BTreeMap;

    fn paops() -> ParseOps {
        ParseOps::new(crate::crypto::default_policy()).unwrap()
    }

    fn write_tree(tree: &TextTree) -> String {
        let mut out = Vec::new();
        tree_write(&mut out, tree, &mut paops()).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn plain_emits_verbatim() {
        assert_eq!(
            write_tree(&vec![TextNode::Plain("hello".into())]),
            "hello\n"
        );
    }

    #[test]
    fn begin_end_wraps_children() {
        let tree = vec![TextNode::BeginEnd {
            keyw: "Agent_007".into(),
            txt: vec![TextNode::Plain("classified".into())],
        }];
        assert_eq!(
            write_tree(&tree),
            "// <( BEGIN Agent_007 )>\nclassified\n// <( END Agent_007 )>\n"
        );
    }

    #[test]
    fn nested_begin_end_preserves_level() {
        // A BeginEnd inside a BeginEnd: the writer recurses; the level
        // counter must balance so subsequent directives are unaffected.
        let tree = vec![TextNode::BeginEnd {
            keyw: "outer".into(),
            txt: vec![TextNode::BeginEnd {
                keyw: "inner".into(),
                txt: vec![TextNode::Plain("body".into())],
            }],
        }];
        let s = write_tree(&tree);
        assert_eq!(
            s,
            "// <( BEGIN outer )>\n// <( BEGIN inner )>\nbody\n// <( END inner )>\n// <( END outer )>\n"
        );
    }

    #[test]
    fn encrypted_with_stored_child_is_single_line() {
        let mut extfields = BTreeMap::new();
        extfields.insert("cipher".to_string(), "aes-256-siv".to_string());
        extfields.insert("pbkdf".to_string(), "$argon2id$v=19".to_string());
        let tree = vec![TextNode::Encrypted {
            keyw: "Agent_007".into(),
            txt: vec![TextNode::Stored {
                keyw: "ct".into(),
                cas: "a1b2c3".into(),
            }],
            extfields,
        }];
        let s = write_tree(&tree);
        // BTreeMap iteration is sorted: cipher before pbkdf.
        assert_eq!(
            s,
            "// <( ENCRYPTED Agent_007 a1b2c3 cipher:aes-256-siv pbkdf:$argon2id$v=19 )>\n"
        );
    }

    #[test]
    fn encrypted_with_data_child_is_multiline() {
        let mut extfields = BTreeMap::new();
        extfields.insert("cipher".to_string(), "aes-256-siv".to_string());
        let tree = vec![TextNode::Encrypted {
            keyw: "Agent_007".into(),
            txt: vec![TextNode::Data(vec![0u8; 16])],
            extfields,
        }];
        let s = write_tree(&tree);
        assert!(
            s.starts_with("// <( ENCRYPTED Agent_007 cipher:aes-256-siv )>\n"),
            "got: {s}"
        );
        assert!(s.contains("// <( DATA "), "got: {s}");
        assert!(s.ends_with("// <( END Agent_007 )>\n"), "got: {s}");
    }

    #[test]
    fn encrypted_with_empty_txt_does_not_panic() {
        // Library consumers can build an empty txt; the writer must
        // fall back to the multiline form instead of indexing.
        let tree = vec![TextNode::Encrypted {
            keyw: "W".into(),
            txt: vec![],
            extfields: BTreeMap::new(),
        }];
        let s = write_tree(&tree);
        assert_eq!(s, "// <( ENCRYPTED W )>\n// <( END W )>\n");
    }

    #[test]
    fn stored_directive_emits_cas_hash() {
        let tree = vec![TextNode::Stored {
            keyw: "Agent_007".into(),
            cas: "deadbeef".into(),
        }];
        assert_eq!(write_tree(&tree), "// <( STORED Agent_007 deadbeef )>\n");
    }

    #[test]
    fn data_splits_into_48_byte_lines() {
        // 100 bytes → chunks of 48 + 48 + 4 → three DATA lines.
        let tree = vec![TextNode::Data(vec![0x41u8; 100])];
        let s = write_tree(&tree);
        let data_lines: Vec<&str> = s.lines().filter(|l| l.contains("DATA")).collect();
        assert_eq!(data_lines.len(), 3, "got: {s}");
        assert!(s.ends_with(" )>\n"));
    }

    #[test]
    fn empty_data_emits_nothing() {
        let tree = vec![TextNode::Data(vec![])];
        assert_eq!(write_tree(&tree), "");
    }

    #[test]
    fn chain_emits_sorted_extfields() {
        let mut extfields = BTreeMap::new();
        extfields.insert("signer".to_string(), "ed25519:9f3a".into());
        extfields.insert("parents".to_string(), "abc".into());
        extfields.insert("payload".to_string(), "def0".into());
        let tree = vec![TextNode::Chain { extfields }];
        let s = write_tree(&tree);
        assert_eq!(
            s,
            "// <( CHAIN parents:abc payload:def0 signer:ed25519:9f3a )>\n"
        );
    }

    #[test]
    fn include_emits_cas_hash() {
        let tree = vec![TextNode::Include {
            hash: "cafe1234".into(),
        }];
        assert_eq!(write_tree(&tree), "// <( INCLUDE cafe1234 )>\n");
    }

    #[test]
    fn conflict_emits_ours_then_theirs() {
        let tree = vec![TextNode::Conflict {
            keyw: "Agent_007".into(),
            ours: vec![TextNode::Plain("our text".into())],
            theirs: vec![TextNode::Plain("their text".into())],
        }];
        let s = write_tree(&tree);
        assert_eq!(
            s,
            "// <( CONFLICT Agent_007 )>\n\
             // <( OURS )>\n\
             our text\n\
             // <( THEIRS )>\n\
             their text\n\
             // <( END Agent_007 )>\n"
        );
    }

    #[test]
    fn immutable_wraps_content_with_mutable_close() {
        let tree = vec![TextNode::Immutable {
            name: "License".into(),
            hashalg: "sha384".into(),
            hash: "ABCDEF".into(),
            txt: vec![TextNode::Plain("(c) 2026".into())],
        }];
        let s = write_tree(&tree);
        assert_eq!(
            s,
            "// <( IMMUTABLE License sha384=ABCDEF )>\n\
             (c) 2026\n\
             // <( MUTABLE License )>\n"
        );
    }

    #[test]
    fn muted_emits_name_and_hash() {
        let tree = vec![TextNode::Muted {
            name: "License".into(),
            hashalg: "sha384".into(),
            hash: "ABCDEF".into(),
        }];
        assert_eq!(write_tree(&tree), "// <( MUTED License sha384=ABCDEF )>\n");
    }

    #[test]
    fn key_unkey_cert_uncert_directives() {
        let tree = vec![
            TextNode::Key {
                name: "grp".into(),
                hashalg: "sha256".into(),
                hash: "11".into(),
            },
            TextNode::Unkey { name: "grp".into() },
            TextNode::Cert {
                name: "ca".into(),
                hashalg: "sha256".into(),
                hash: "22".into(),
            },
            TextNode::Uncert { name: "ca".into() },
        ];
        assert_eq!(
            write_tree(&tree),
            "// <( KEY grp sha256=11 )>\n\
             // <( UNKEY grp )>\n\
             // <( CERT ca sha256=22 )>\n\
             // <( UNCERT ca )>\n"
        );
    }

    #[test]
    fn custom_separators_flow_through() {
        let mut p = paops();
        p.separators.left = "# <[".into();
        p.separators.right = "]>".into();
        let tree = vec![TextNode::BeginEnd {
            keyw: "W".into(),
            txt: vec![],
        }];
        let mut out = Vec::new();
        tree_write(&mut out, &tree, &mut p).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "# <[ BEGIN W ]>\n# <[ END W ]>\n"
        );
    }

    #[test]
    fn io_error_propagates_as_result() {
        // Audit A8: a write failure must surface as Err, not panic.
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut p = paops();
        let tree = vec![TextNode::Plain("x".into())];
        let r = tree_write(&mut FailingWriter, &tree, &mut p);
        assert!(r.is_err(), "write failure must propagate, got {r:?}");
    }

    #[test]
    fn empty_tree_writes_nothing() {
        assert_eq!(write_tree(&vec![]), "");
    }
}
