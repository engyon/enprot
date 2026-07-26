//! Fuzz the parser: feed random bytes, assert no panic.
//! Round-trip identity is NOT asserted (random bytes rarely produce
//! identical output); the goal is just to surface panics on
//! adversarial inputs. See TODO.roadmap/54.
//!
//! Run: cargo fuzz run parse_no_panic

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut paops = match enprot::etree::ParseOps::new(Box::new(
        enprot::crypto::CryptoPolicyDefault {},
    )) {
        Ok(p) => p,
        Err(_) => return,
    };
    paops.runtime.fname = "<fuzz>".into();
    let _ = enprot::etree::parse(Cursor::new(data), &mut paops);
});
