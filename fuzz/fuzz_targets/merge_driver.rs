//! Fuzz the merge driver: feed three arbitrary blobs as ancestor /
//! ours / theirs, assert no panic. Realistic conflict structures
//! rarely emerge from pure random bytes; the goal is to surface
//! panics on adversarial shapes. See TODO.completion/13.
//!
//! Run: cargo fuzz run merge_driver

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Split the fuzz input into three slices at sentinel bytes (0xFF).
    // If we have fewer than 2 sentinels, fall back to thirds.
    let splits: Vec<usize> = data
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == 0xFF)
        .map(|(i, _)| i)
        .collect();
    let (ancestor, ours, theirs) = match splits.as_slice() {
        [a, b] => (&data[..*a], &data[a + 1..*b], &data[b + 1..]),
        _ => {
            let n = data.len();
            let a = n / 3;
            let b = 2 * n / 3;
            (&data[..a], &data[a..b], &data[b..])
        }
    };

    let new_paops = || {
        let mut p = enprot::etree::ParseOps::new(Box::new(
            enprot::crypto::CryptoPolicyDefault {},
        ))
        .unwrap();
        p.runtime.fname = "<fuzz>".into();
        p
    };

    let ancestor = String::from_utf8_lossy(ancestor);
    let ours = String::from_utf8_lossy(ours);
    let theirs = String::from_utf8_lossy(theirs);

    let mut p1 = new_paops();
    let mut p2 = new_paops();
    let mut p3 = new_paops();
    let a_tree = enprot::etree::parse(Cursor::new(ancestor.as_bytes()), &mut p1);
    let o_tree = enprot::etree::parse(Cursor::new(ours.as_bytes()), &mut p2);
    let t_tree = enprot::etree::parse(Cursor::new(theirs.as_bytes()), &mut p3);

    if let (Ok(a), Ok(o), Ok(t)) = (a_tree, o_tree, t_tree) {
        let _ = enprot::merge::merge_trees(&a, &o, &t);
    }
});
