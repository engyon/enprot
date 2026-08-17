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
use std::io::{BufRead, Write};

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

// ---------------------------------------------------------------------
// Streaming transform + write (TODO.complete/35)
// ---------------------------------------------------------------------

/// The closer a buffered block is still waiting for.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum BlockCloser {
    End,
    Mutable,
}

/// True when an `ENCRYPTED` directive opens a multi-line block (i.e.
/// carries only the WORD, with the payload on following DATA lines)
/// rather than closing itself on one line with an inline CAS hash.
///
/// Mirrors `parse_encrypted`'s classification: the trailing run of
/// `:`-containing tokens are extfields, and the block opens iff
/// exactly one non-extfield parameter (the WORD) remains. The
/// property test below pins this to the in-memory parser's behavior.
fn encrypted_opens_block(rest: &[&str]) -> bool {
    let mut ext = 0;
    for tok in rest.iter().rev() {
        if tok.contains(':') {
            ext += 1;
        } else {
            break;
        }
    }
    rest.len() - ext == 1
}

/// Classify a directive line's keyword into the closer it needs, if
/// it opens a buffered block. `None` = single-line directive.
fn opener_for(keyword: &str, rest: &[&str]) -> Option<BlockCloser> {
    match keyword {
        "BEGIN" | "CONFLICT" => Some(BlockCloser::End),
        "IMMUTABLE" => Some(BlockCloser::Mutable),
        "ENCRYPTED" if encrypted_opens_block(rest) => Some(BlockCloser::End),
        _ => None,
    }
}

/// Streaming transform + write: bounded-memory alternative to
/// `parse` → `transform` → `tree_write`.
///
/// Plain lines between blocks are written as they are read; each
/// top-level block (or single-line directive) is buffered, then run
/// through the *unmodified* in-memory `parse`/`transform`/`tree_write`
/// on exactly its own lines. Memory is `O(largest block)`, not
/// `O(file)`. Because every block reuses the in-memory path on the
/// same bytes, successful output is byte-identical to the full
/// pipeline by construction — the property test pins it.
///
/// Divergences from the in-memory path (documented on the
/// `--streaming` flag): error messages for problems inside a block
/// carry the block-relative line number, and a mid-file failure can
/// leave a partially written output (the in-memory path leaves it
/// empty; both truncate the file at open).
pub fn transform_stream<R: BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    paops: &mut crate::etree::ParseOps,
) -> Result<()> {
    let mut reader = reader;
    let mut buf: Vec<String> = Vec::new();
    let mut closers: Vec<BlockCloser> = Vec::new();

    let separators = crate::etree::Separators {
        left: paops.separators.left.clone(),
        right: paops.separators.right.clone(),
    };
    let emit_block =
        |buf: &[String], writer: &mut W, paops: &mut crate::etree::ParseOps| -> Result<()> {
            let joined: Vec<u8> = buf
                .iter()
                .map(|l| format!("{l}\n"))
                .collect::<Vec<_>>()
                .concat()
                .into_bytes();
            let tree = crate::etree::parse(&joined[..], paops)?;
            let tree = crate::etree::transform(&tree, paops)?;
            crate::etree::tree_write(writer, &tree, paops)
        };

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let line = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();

        let trimmed = line.trim_start();
        let is_directive = trimmed.starts_with(&separators.left);

        if closers.is_empty() {
            // Top level.
            if !is_directive {
                // Plain text: in-memory parse folds consecutive lines
                // into one Plain node and tree_write writeln!s it —
                // byte-identical to writing each line + '\n'.
                writeln!(writer, "{line}")?;
                continue;
            }
            // A directive at top level: if it opens a block, start
            // buffering; otherwise it is a self-contained one-liner
            // that still goes through transform (e.g. STORED under
            // fetch), as a single-line block.
            if let Some(closer) = directive_closer(&line, &separators) {
                buf.push(line);
                closers.push(closer);
            } else {
                emit_block(&[line], writer, paops)?;
            }
            continue;
        }

        // Inside a buffered block: append; track nested openers and
        // the matching closer.
        buf.push(line.clone());
        if is_directive && let Some((kw, rest)) = split_directive(&line, &separators) {
            if let Some(closer) = opener_for(&kw, &rest) {
                closers.push(closer);
            } else if kw == "END" || kw == "MUTABLE" {
                let want = if kw == "END" {
                    BlockCloser::End
                } else {
                    BlockCloser::Mutable
                };
                match closers.last() {
                    Some(top) if *top == want => {
                        closers.pop();
                    }
                    // Malformed nesting: keep buffering to EOF and let
                    // parse produce the same class of error the full
                    // document would.
                    _ => {}
                }
                if closers.is_empty() {
                    emit_block(&buf, writer, paops)?;
                    buf.clear();
                }
            }
        }
    }

    if !buf.is_empty() {
        // EOF with an open block — parse reports "Unclosed section"
        // exactly like the full-document path.
        emit_block(&buf, writer, paops)?;
    }
    Ok(())
}

/// Split a directive line into (keyword, rest-tokens); `None` when
/// the line is not a directive.
fn split_directive<'a>(
    line: &'a str,
    separators: &crate::etree::Separators,
) -> Option<(String, Vec<&'a str>)> {
    let trimmed = line.trim_start();
    let after_left = trimmed.strip_prefix(&separators.left)?;
    let inner = after_left
        .strip_suffix(&separators.right)
        .unwrap_or(after_left);
    let mut parts = inner.split_whitespace();
    let kw = parts.next()?.to_string();
    Some((kw, parts.collect()))
}

/// The closer a top-level directive line needs, if it opens a block.
fn directive_closer(line: &str, separators: &crate::etree::Separators) -> Option<BlockCloser> {
    let (kw, rest) = split_directive(line, separators)?;
    opener_for(&kw, &rest)
}

#[cfg(test)]
mod transform_tests {
    use super::*;
    use crate::crypto::CryptoPolicyDefault;
    use crate::etree::ParseOps;
    use std::io::Cursor;

    fn paops() -> ParseOps {
        let mut p = ParseOps::new(Box::new(CryptoPolicyDefault {})).unwrap();
        p.runtime.fname = "<stream>".into();
        p
    }

    /// The in-memory reference: parse → transform → tree_write.
    fn in_memory(input: &str, paops: &mut ParseOps) -> Vec<u8> {
        let tree = crate::etree::parse(Cursor::new(input.as_bytes()), paops).unwrap();
        let tree = crate::etree::transform(&tree, paops).unwrap();
        let mut out = Vec::new();
        crate::etree::tree_write(&mut out, &tree, paops).unwrap();
        out
    }

    fn streaming(input: &str, paops: &mut ParseOps) -> Vec<u8> {
        let mut out = Vec::new();
        transform_stream(Cursor::new(input.as_bytes()), &mut out, paops).unwrap();
        out
    }

    #[test]
    fn byte_identical_on_mixed_document() {
        let input = "intro line\n\
                     // <( CHAIN parents:ab signer:ed25519:9f )>\n\
                     // <( BEGIN W1 )>\n\
                     w1 content\n\
                     more w1\n\
                     // <( BEGIN W2 )>\n\
                     nested content\n\
                     // <( END W2 )>\n\
                     // <( END W1 )>\n\
                     between blocks\n\
                     // <( IMMUTABLE L sha384=AB )>\n\
                     license text\n\
                     // <( MUTABLE L )>\n\
                     // <( STORED W3 cafe1234 )>\n\
                     trailing text\n";
        let a = in_memory(input, &mut paops());
        let b = streaming(input, &mut paops());
        assert_eq!(
            a,
            b,
            "\nin-memory: {}\nstreaming: {}",
            String::from_utf8_lossy(&a),
            String::from_utf8_lossy(&b)
        );
    }

    #[test]
    fn byte_identical_with_store_transform() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = paops();
        p.io.casdir = dir.path().to_path_buf();
        p.io.set_local_casdir(dir.path().to_path_buf());
        p.transforms.store.insert("W1".into());
        let input = "// <( BEGIN W1 )>\nsecret text\n// <( END W1 )>\nplain\n";
        let a = in_memory(input, &mut p);
        let mut p2 = paops();
        p2.io.casdir = dir.path().to_path_buf();
        p2.io.set_local_casdir(dir.path().to_path_buf());
        p2.transforms.store.insert("W1".into());
        let b = streaming(input, &mut p2);
        assert_eq!(a, b);
        // The block actually moved to CAS (STORED in output).
        let s = String::from_utf8_lossy(&b);
        assert!(s.contains("STORED"), "got: {s}");
    }

    #[test]
    fn byte_identical_with_encrypted_fetch_round_trip() {
        // Build an encrypted block via the in-memory path, then fetch
        // it back through both paths and compare.
        let dir = tempfile::tempdir().unwrap();
        let mut p = paops();
        p.io.casdir = dir.path().to_path_buf();
        p.io.set_local_casdir(dir.path().to_path_buf());
        p.transforms.encrypt.insert("W".into());
        p.passwords.insert("W".into(), "pw".into());
        let input = "// <( BEGIN W )>\nhello\n// <( END W )>\n";
        let enc = in_memory(input, &mut p);

        let mut f = paops();
        f.io.casdir = dir.path().to_path_buf();
        f.io.set_local_casdir(dir.path().to_path_buf());
        f.transforms.fetch.insert("W".into());
        f.transforms.decrypt.insert("W".into());
        f.passwords.insert("W".into(), "pw".into());
        let enc_str = String::from_utf8_lossy(&enc).to_string();

        let mut f2 = paops();
        f2.io.casdir = dir.path().to_path_buf();
        f2.io.set_local_casdir(dir.path().to_path_buf());
        f2.transforms.fetch.insert("W".into());
        f2.transforms.decrypt.insert("W".into());
        f2.passwords.insert("W".into(), "pw".into());
        assert_eq!(
            in_memory(&enc_str, &mut f),
            streaming(&enc_str, &mut f2),
            "fetch+decrypt round trip must be byte-identical"
        );
    }

    #[test]
    fn single_line_encrypted_is_not_an_opener() {
        assert!(!encrypted_opens_block(&["W", &"a".repeat(64)]));
        assert!(encrypted_opens_block(&["W"]));
        assert!(encrypted_opens_block(&["W", "cipher:aes-256-siv"]));
        assert!(!encrypted_opens_block(&[]));
    }

    #[test]
    fn unclosed_block_errors_like_the_full_path() {
        let input = "// <( BEGIN W )>\ncontent\n";
        let mut p = paops();
        assert!(crate::etree::parse(Cursor::new(input.as_bytes()), &mut p).is_err());
        let mut p2 = paops();
        let mut out = Vec::new();
        assert!(transform_stream(Cursor::new(input.as_bytes()), &mut out, &mut p2).is_err());
    }

    #[test]
    fn top_level_end_directive_errors_via_micro_block() {
        let input = "text\n// <( END W )>\n";
        let mut p = paops();
        assert!(crate::etree::parse(Cursor::new(input.as_bytes()), &mut p).is_err());
        let mut p2 = paops();
        let mut out = Vec::new();
        assert!(transform_stream(Cursor::new(input.as_bytes()), &mut out, &mut p2).is_err());
    }

    #[test]
    fn empty_input_writes_nothing() {
        assert_eq!(streaming("", &mut paops()), b"");
    }

    #[test]
    fn missing_trailing_newline_normalized_identically() {
        let input = "only line";
        assert_eq!(
            in_memory(input, &mut paops()),
            streaming(input, &mut paops())
        );
    }
}
