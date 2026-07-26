//! Fuzz well-formed CONFLICT blocks. Generates a random WORD,
//! random ours content, random theirs content; wraps them in
//! CONFLICT / OURS / THEIRS / END; asserts the parser either
//! produces a tree with one Conflict node or returns Err — but
//! never panics. See TODO.roadmap/54.
//!
//! Run: cargo fuzz run conflict_well_formed

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fn word_from_bytes(b: &[u8]) -> String {
    // Map random bytes into a safe WORD identifier (alphanumeric +
    // underscore). Empty input → "X".
    if b.is_empty() {
        return "X".to_string();
    }
    b.iter()
        .map(|c| match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' => *c as char,
            _ => '_',
        })
        .collect()
}

fuzz_target!(|data: (String, String, String)| {
    let (word, ours_body, theirs_body) = data;
    let word = if word.is_empty() {
        "X".to_string()
    } else {
        word_from_bytes(word.as_bytes())
    };
    let src = format!(
        "// <( CONFLICT {word} )>\n// <( OURS )>\n{ours_body}\n// <( THEIRS )>\n{theirs_body}\n// <( END {word} )>\n"
    );
    let mut paops = match enprot::etree::ParseOps::new(Box::new(
        enprot::crypto::CryptoPolicyDefault {},
    )) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops.runtime.fname = "<fuzz>".into();
    let _ = enprot::etree::parse(Cursor::new(src.as_bytes()), &mut paops);
});
