//! Streaming parser scaffold for EPT (TODO.complete/05-streaming-io).
//!
//! Status: **scaffold** — defines the `ParseEvent` enum and `Parser`
//! iterator API, but does NOT replace the in-memory `etree::parse`.
//! The production code path stays on `parse()` until the streaming
//! transform layer is ready.
//!
//! The enum mirrors the `TextNode` variants but as a flat stream
//! (no children — the caller maintains the tree if needed). This is
//! the shape that a streaming `transform()` would consume.
//!
//! ## Why an enum instead of reusing TextNode?
//!
//! `TextNode` is recursive (`Encrypted { txt: TextTree }`) — each
//! variant owns its children. A streaming parser must NOT hold the
//! whole tree; it emits events one at a time. The tree is rebuilt
//! (if needed) by the consumer's fold.

use std::collections::BTreeMap;
use std::io::BufRead;

use crate::error::Result;
use crate::etree::ParseOps;

/// One event from the streaming EPT parser.
///
/// Events are emitted in document order. `BeginBlock` and `EndBlock`
/// are properly nested; the consumer can track depth via a stack.
#[derive(Debug, Clone)]
pub enum ParseEvent {
    /// A line of plain text (host-language content, no directives).
    Plain(String),

    /// Opens a BEGIN/END segment. Followed by the body events, then
    /// `EndBlock` with the same WORD.
    BeginBlock {
        word: String,
    },

    /// Closes the matching BEGIN.
    EndBlock {
        word: String,
    },

    /// Opens an ENCRYPTED segment. Followed by a `Data` or
    /// `StoredRef` event, then `EndBlock`.
    Encrypted {
        word: String,
        extfields: BTreeMap<String, String>,
    },

    /// A CAS pointer inside a STORED directive (or an ENCRYPTED block
    /// whose ciphertext is in CAS rather than inline).
    StoredRef {
        word: String,
        hash: String,
    },

    /// One base64-encoded DATA line (ciphertext chunk).
    Data(Vec<u8>),

    /// A CHAIN anchor block.
    Chain {
        extfields: BTreeMap<String, String>,
    },

    /// An IMMUTABLE block opening.
    Immutable {
        name: String,
        hashalg: String,
        hash: String,
    },

    /// Closes an IMMUTABLE block (MUTABLE directive).
    Mutable {
        name: String,
    },

    /// A MUTED block (CAS-referenced immutable content).
    Muted {
        name: String,
        hashalg: String,
        hash: String,
    },

    /// A merge-driver CONFLICT block opening.
    Conflict {
        word: String,
    },

    /// Side marker inside a CONFLICT block.
    Ours,
    Theirs,

    /// A cross-file INCLUDE directive.
    Include {
        hash: String,
    },
}

/// Streaming EPT parser. Reads lines from a `BufRead` and emits
/// `ParseEvent`s one at a time.
///
/// Usage (once the transform layer is migrated):
///
/// ```ignore
/// let parser = Parser::new(reader, &separators);
/// for event in parser {
///     match event? {
///         ParseEvent::BeginBlock { word } => { /* ... */ },
///         ParseEvent::Data(bytes) => { /* ... */ },
///         _ => {}
///     }
/// }
/// ```
///
/// ## Not yet implemented
///
/// The actual line-parsing logic is the same as `etree::parse`. The
/// full migration plan is in TODO.complete/05-streaming-io. This
/// struct's body currently returns an error pointing to the TODO.
pub struct Parser<R: BufRead> {
    _reader: R,
    _separators: crate::etree::Separators,
    _stack: Vec<String>,
}

impl<R: BufRead> Parser<R> {
    /// Create a new streaming parser over `reader`.
    pub fn new(reader: R, separators: crate::etree::Separators) -> Self {
        Parser {
            _reader: reader,
            _separators: separators,
            _stack: Vec::new(),
        }
    }

    /// Returns the next parse event, or `None` at EOF.
    ///
    /// Currently unimplemented — returns an error directing to
    /// TODO.complete/05. The plan is to share the directive-matching
    /// logic from `etree::parse` but emit events instead of building
    /// a TextTree.
    pub fn next_event(&mut self, _paops: &mut ParseOps) -> Result<Option<ParseEvent>> {
        // TODO(streaming): port the directive-matching logic from
        // etree::parse.rs to emit ParseEvent values instead of pushing
        // TextNode children. The line-reading loop, separator
        // matching, and Command dispatch all stay; only the output
        // shape changes.
        Err(crate::error::Error::msg(
            "streaming Parser not yet implemented (TODO.complete/05)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_is_debug() {
        let e = ParseEvent::Plain("hello".into());
        assert!(format!("{e:?}").contains("Plain"));
    }

    #[test]
    fn parse_event_clone_works() {
        let e = ParseEvent::BeginBlock {
            word: "SECRET".into(),
        };
        let e2 = e.clone();
        if let ParseEvent::BeginBlock { word } = e2 {
            assert_eq!(word, "SECRET");
        } else {
            panic!("clone should preserve variant");
        }
    }

    #[test]
    fn parser_new_does_not_read() {
        let input = std::io::Cursor::new(b"hello\n");
        let seps = crate::etree::Separators {
            left: "// <(".into(),
            right: ")>".into(),
        };
        let _p = Parser::new(input, seps);
        // Construction is zero-cost; no reads happen until next_event.
    }
}
