//! Fuzz CAS hash validation: feed random strings as CAS hashes.
//! Asserts no panic on malformed hex, empty strings, very long
//! strings, etc.
//!
//! Run: cargo fuzz run cas_hash_validation

#![no_main]

use enprot::cas::CasStore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let hash = String::from_utf8_lossy(data);
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let store = enprot::cas::LocalCas::new(dir.path().to_path_buf());
    let policy = enprot::crypto::default_policy();
    let _ = store.load(&hash, &*policy);
    let _ = store.delete(&hash);
    let _ = store.contains(&hash, &*policy);
});
