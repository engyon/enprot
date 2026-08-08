//! Fuzz the parser with non-default separators. The first 4 bytes of
//! input become the left/right separator pair; the rest is the file
//! content. Asserts no panic on adversarial separator + content combos.
//!
//! Run: cargo fuzz run separator_round_trip

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let left = String::from_utf8_lossy(&data[..2]);
    let right = String::from_utf8_lossy(&data[2..4]);
    let content = String::from_utf8_lossy(&data[4..]);

    let mut paops = match enprot::etree::ParseOps::new(Box::new(
        enprot::crypto::CryptoPolicyDefault {},
    )) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops.separators.left = left.into_owned();
    paops.separators.right = right.into_owned();
    paops.runtime.fname = "<fuzz>".into();
    let _ = enprot::etree::parse(Cursor::new(content.into_owned().into_bytes()), &mut paops);
});
