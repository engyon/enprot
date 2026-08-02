//! Streaming parser for EPT (TODO.complete/05-streaming-io).
//!
//! Implements a real streaming parser that emits [`ParseEvent`]s one
//! at a time from a [`BufRead`], without building the full
//! [`TextTree`](crate::etree::TextTree) in memory.
//!
//! The parser shares the directive-matching logic with the in-memory
//! [`etree::parse`](crate::etree::parse) function but emits flat
//! events instead of pushing children. Consumers can rebuild the tree
//! by stacking events, or process them directly (the streaming
//! transform use case).

use std::collections::BTreeMap;
use std::io::BufRead;

use crate::error::Result;

/// One event from the streaming EPT parser.
#[derive(Debug, Clone)]
pub enum ParseEvent {
    Plain(String),
    BeginBlock {
        word: String,
    },
    EndBlock {
        word: String,
    },
    Encrypted {
        word: String,
        extfields: BTreeMap<String, String>,
    },
    StoredRef {
        word: String,
        hash: String,
    },
    Data(Vec<u8>),
    Chain {
        extfields: BTreeMap<String, String>,
    },
    Immutable {
        name: String,
        hashalg: String,
        hash: String,
    },
    Mutable {
        name: String,
    },
    Muted {
        name: String,
        hashalg: String,
        hash: String,
    },
    Conflict {
        word: String,
    },
    Ours,
    Theirs,
    Include {
        hash: String,
    },
    Unknown {
        keyword: String,
        args: Vec<String>,
    },
}

/// Streaming EPT parser. Reads lines from a `BufRead` and emits
/// `ParseEvent`s one at a time.
pub struct Parser<R: BufRead> {
    reader: R,
    separators: crate::etree::Separators,
    pending: std::collections::VecDeque<ParseEvent>,
    plain_buf: String,
    done: bool,
}

impl<R: BufRead> Parser<R> {
    pub fn new(reader: R, separators: crate::etree::Separators) -> Self {
        Parser {
            reader,
            separators,
            pending: std::collections::VecDeque::new(),
            plain_buf: String::new(),
            done: false,
        }
    }

    /// Returns the next parse event, or `None` at EOF.
    pub fn next_event(&mut self) -> Result<Option<ParseEvent>> {
        // Return buffered events first.
        if let Some(ev) = self.pending.pop_front() {
            return Ok(Some(ev));
        }

        while !self.done {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                self.done = true;
                break;
            }

            // Strip trailing newline.
            let line = line.trim_end_matches('\n');
            let line = line.trim_end_matches('\r');

            let trimmed = line.trim_start();
            if !trimmed.starts_with(&self.separators.left) {
                // Non-directive line → accumulate.
                if !self.plain_buf.is_empty() {
                    self.plain_buf.push('\n');
                }
                self.plain_buf.push_str(line);
                continue;
            }

            // Directive line. Flush accumulated plain text first.
            self.flush_plain();

            // Parse the directive.
            let after_left = trimmed
                .strip_prefix(&self.separators.left)
                .unwrap_or(trimmed);
            let inner = after_left
                .strip_suffix(&self.separators.right)
                .unwrap_or(after_left);
            let mut parts = inner.split_whitespace();
            let kw = match parts.next() {
                Some(k) => k,
                None => continue,
            };
            let rest: Vec<&str> = parts.collect();
            let event = self.classify_directive(kw, &rest);
            return Ok(Some(event));
        }

        // EOF — flush remaining plain text.
        self.flush_plain();
        if let Some(ev) = self.pending.pop_front() {
            return Ok(Some(ev));
        }
        Ok(None)
    }

    fn flush_plain(&mut self) {
        if !self.plain_buf.is_empty() {
            let text = std::mem::take(&mut self.plain_buf);
            self.pending.push_back(ParseEvent::Plain(text));
        }
    }

    fn classify_directive(&self, kw: &str, rest: &[&str]) -> ParseEvent {
        match kw {
            "BEGIN" => {
                let word = rest.first().copied().unwrap_or("").to_string();
                ParseEvent::BeginBlock { word }
            }
            "END" => {
                let word = rest.first().copied().unwrap_or("").to_string();
                ParseEvent::EndBlock { word }
            }
            "ENCRYPTED" => {
                let word = rest.first().copied().unwrap_or("").to_string();
                let extfields = self.parse_extfields(&rest[1..]);
                ParseEvent::Encrypted { word, extfields }
            }
            "STORED" => {
                let word = rest.first().copied().unwrap_or("").to_string();
                let hash = rest.get(1).copied().unwrap_or("").to_string();
                ParseEvent::StoredRef { word, hash }
            }
            "DATA" => {
                let b64 = rest.first().copied().unwrap_or("");
                let bytes = crate::utils::base64_decode(b64).unwrap_or_default();
                ParseEvent::Data(bytes)
            }
            "CHAIN" => {
                let extfields = self.parse_extfields(rest);
                ParseEvent::Chain { extfields }
            }
            "IMMUTABLE" => {
                let name = rest.first().copied().unwrap_or("").to_string();
                let (hashalg, hash) = rest
                    .get(1)
                    .and_then(|s| s.split_once('='))
                    .map(|(alg, h)| (alg.to_string(), h.to_string()))
                    .unwrap_or_default();
                ParseEvent::Immutable {
                    name,
                    hashalg,
                    hash,
                }
            }
            "MUTABLE" => {
                let name = rest.first().copied().unwrap_or("").to_string();
                ParseEvent::Mutable { name }
            }
            "MUTED" => {
                let name = rest.first().copied().unwrap_or("").to_string();
                let (hashalg, hash) = rest
                    .get(1)
                    .and_then(|s| s.split_once('='))
                    .map(|(alg, h)| (alg.to_string(), h.to_string()))
                    .unwrap_or_default();
                ParseEvent::Muted {
                    name,
                    hashalg,
                    hash,
                }
            }
            "CONFLICT" => {
                let word = rest.first().copied().unwrap_or("").to_string();
                ParseEvent::Conflict { word }
            }
            "OURS" => ParseEvent::Ours,
            "THEIRS" => ParseEvent::Theirs,
            "INCLUDE" => {
                let hash = rest.first().copied().unwrap_or("").to_string();
                ParseEvent::Include { hash }
            }
            _ => ParseEvent::Unknown {
                keyword: kw.to_string(),
                args: rest.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    /// Parse colon-separated extfields (key:value pairs) from a slice.
    fn parse_extfields(&self, fields: &[&str]) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for f in fields {
            if let Some((k, v)) = f.split_once(':') {
                map.insert(k.to_string(), v.to_string());
            }
        }
        map
    }
}

/// Iterator-style adapter for Parser.
impl<R: BufRead> Iterator for Parser<R> {
    type Item = Result<ParseEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_event() {
            Ok(Some(ev)) => Some(Ok(ev)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn default_seps() -> crate::etree::Separators {
        crate::etree::Separators {
            left: "// <(".into(),
            right: ")>".into(),
        }
    }

    #[test]
    fn plain_text_emits_one_event() {
        let input = Cursor::new("hello world\n");
        let mut parser = Parser::new(input, default_seps());
        let ev = parser.next_event().unwrap().unwrap();
        assert!(matches!(ev, ParseEvent::Plain(ref t) if t.contains("hello")));
        assert!(parser.next_event().unwrap().is_none());
    }

    #[test]
    fn begin_end_emits_events() {
        let input = Cursor::new("// <( BEGIN SECRET )>\nplaintext\n// <( END SECRET )>\n");
        let seps = default_seps();
        let parser = Parser::new(input, seps);
        let events: Vec<_> = parser.collect::<Result<_>>().unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            ParseEvent::BeginBlock { word } if word == "SECRET"
        )));
        assert!(events.iter().any(|e| matches!(e, ParseEvent::Plain(_))));
        assert!(events.iter().any(|e| matches!(
            e,
            ParseEvent::EndBlock { word } if word == "SECRET"
        )));
    }

    #[test]
    fn encrypted_with_extfields_parses() {
        let input = Cursor::new(
            "// <( ENCRYPTED SECRET cipher:aes-256-siv )>\n// <( DATA abc= )>\n// <( END SECRET )>\n",
        );
        let seps = default_seps();
        let parser = Parser::new(input, seps);
        let events: Vec<_> = parser.collect::<Result<_>>().unwrap();
        let enc = events
            .iter()
            .find(|e| matches!(e, ParseEvent::Encrypted { .. }));
        assert!(enc.is_some());
        if let Some(ParseEvent::Encrypted { word, extfields }) = enc {
            assert_eq!(word, "SECRET");
            assert_eq!(extfields.get("cipher"), Some(&"aes-256-siv".to_string()));
        }
        assert!(events.iter().any(|e| matches!(e, ParseEvent::Data(_))));
    }

    #[test]
    fn stored_directive_parses() {
        let input = Cursor::new("// <( STORED SECRET abc123 )>\n");
        let seps = default_seps();
        let mut parser = Parser::new(input, seps);
        let ev = parser.next_event().unwrap().unwrap();
        match ev {
            ParseEvent::StoredRef { word, hash } => {
                assert_eq!(word, "SECRET");
                assert_eq!(hash, "abc123");
            }
            _ => panic!("expected StoredRef, got {ev:?}"),
        }
    }

    #[test]
    fn chain_directive_parses() {
        let input = Cursor::new("// <( CHAIN index:1 signer:ed25519:abc )>\n");
        let seps = default_seps();
        let mut parser = Parser::new(input, seps);
        let ev = parser.next_event().unwrap().unwrap();
        match ev {
            ParseEvent::Chain { extfields } => {
                assert_eq!(extfields.get("index"), Some(&"1".to_string()));
                assert_eq!(extfields.get("signer"), Some(&"ed25519:abc".to_string()));
            }
            _ => panic!("expected Chain, got {ev:?}"),
        }
    }

    #[test]
    fn multiline_plain_text_accumulates() {
        let input = Cursor::new("line one\nline two\nline three\n");
        let seps = default_seps();
        let mut parser = Parser::new(input, seps);
        let ev = parser.next_event().unwrap().unwrap();
        match ev {
            ParseEvent::Plain(text) => {
                assert!(text.contains("line one"));
                assert!(text.contains("line two"));
                assert!(text.contains("line three"));
            }
            _ => panic!("expected Plain, got {ev:?}"),
        }
    }
}
