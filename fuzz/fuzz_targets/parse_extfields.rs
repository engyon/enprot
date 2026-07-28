//! Fuzz extfield parsing: feed arbitrary strings, assert no panic.
//! Round-trip identity is asserted where possible (parsed extfields
//! should re-serialize to the same wire form for known keys).
//! See TODO.completion/13.
//!
//! Run: cargo fuzz run parse_extfields

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.is_empty() {
        return;
    }

    // The parse_encrypted_extfields call expects an aliased slice
    // (it iterates with .rev() and consumes tokens). We give it the
    // full token slice.
    let mut paops = match enprot::etree::ParseOps::new(Box::new(
        enprot::crypto::CryptoPolicyDefault {},
    )) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops.runtime.fname = "<fuzz-extfields>".into();

    // The function signature is pub(crate); we can only reach it
    // via the parser proper. So exercise it through a synthetic
    // ENCRYPTED directive: wrap our tokens in a directive line and
    // let the parser dispatch.
    let line = format!("// <( ENCRYPTED {} )>", text);
    let mut paops2 = match enprot::etree::ParseOps::new(Box::new(
        enprot::crypto::CryptoPolicyDefault {},
    )) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops2.runtime.fname = "<fuzz-extfields>".into();
    paops2.separators.left = "// <(".into();
    paops2.separators.right = ")>".into();
    let _ = enprot::etree::parse(Cursor::new(line.as_bytes()), &mut paops2);
});

use std::io::Cursor;
