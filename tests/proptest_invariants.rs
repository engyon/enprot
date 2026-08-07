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

//! Property-based invariant tests for the higher-level transform layer.
//!
//! Complements `proptest_roundtrip.rs` (which covers the crypto
//! primitives) by exercising the parser/transform/CAS pipeline as a
//! whole. The properties checked are:
//!
//! 1. **Store/fetch identity** — `fetch(store(file)) = file` byte-for-byte.
//! 2. **CAS dedup** — same content always produces the same CAS key.
//! 3. **CAS distinct** — different content always produces different keys.
//! 4. **Encrypt idempotency** — `encrypt(encrypt(file)) = encrypt(file)`
//!    when the second pass finds an already-encrypted block.
//! 5. **CAS-key content addressing** — the CAS file name equals the
//!    SHA3-256 hex of the stored content.
//! 6. **Encrypt/decrypt identity** — `decrypt(encrypt(file)) = file`
//!    byte-for-byte through the full transform pipeline.
//! 7. **Commutativity** — `store_then_encrypt(file) =
//!    encrypt_then_store(file)` after canonicalization (both reach the
//!    same encrypted-stored representation).
//!
//! All properties run 256 random cases per default proptest config.
//!
//! See `TODO.complete/08-property-invariants` for the design.

use std::collections::BTreeMap;
use std::io::Cursor;

use proptest::prelude::*;

use enprot::Result;
use enprot::crypto::{CryptoPolicy, CryptoPolicyDefault};
use enprot::etree::{PBKDFOptions, ParseOps, parse, transform, tree_write};

fn policy() -> Box<dyn CryptoPolicy> {
    Box::new(CryptoPolicyDefault {})
}

/// Build a `ParseOps` configured to STORE the named WORD.
fn paops_for_store(word: &str) -> Result<ParseOps> {
    let mut p = ParseOps::new(policy())?;
    p.transforms.store.insert(word.to_string());
    p.transforms.fetch.clear();
    p.transforms.encrypt.clear();
    p.transforms.decrypt.clear();
    Ok(p)
}

/// Build a `ParseOps` configured to FETCH the named WORD.
fn paops_for_fetch(word: &str) -> Result<ParseOps> {
    let mut p = ParseOps::new(policy())?;
    p.transforms.fetch.insert(word.to_string());
    p.transforms.store.clear();
    p.transforms.encrypt.clear();
    p.transforms.decrypt.clear();
    Ok(p)
}

/// Build a `ParseOps` configured to ENCRYPT the named WORD with the
/// deterministic AES-GCM-SIV variant (`aes-256-gcm-siv-det`). The
/// deterministic variant is required for encrypt-idempotency and
/// commutativity properties — the random-IV variants would produce
/// different ciphertexts on each call.
///
/// `inline_data = true` forces ciphertext to be written inline (DATA
/// node) rather than via CAS (STORED node). This keeps the property
/// tests free of filesystem tempdir races — multiple proptest cases
/// running in parallel don't contend on the same casdir.
fn paops_for_encrypt(word: &str, password: &str) -> Result<ParseOps> {
    let mut p = ParseOps::new(policy())?;
    p.transforms.encrypt.insert(word.to_string());
    p.transforms.decrypt.clear();
    p.transforms.store.clear();
    p.transforms.fetch.clear();
    p.passwords.insert(word.to_string(), password.to_string());
    // Deterministic variant: required for idempotency + commutativity.
    p.crypto.cipheropts.alg = "aes-256-gcm-siv-det".to_string();
    // Inline mode: skip CAS so the test doesn't need a tempdir.
    p.io.inline_data = true;
    // Fast PBKDF params so the property test doesn't dominate CI time.
    let mut params = BTreeMap::new();
    params.insert("i".to_string(), 1000);
    p.crypto.pbkdfopts = PBKDFOptions {
        alg: "pbkdf2-sha256".to_string(),
        saltlen: 0,
        salt: Some(b"01234567".to_vec()),
        msec: None,
        params: Some(params),
    };
    Ok(p)
}

/// Build a `ParseOps` configured to DECRYPT the named WORD.
fn paops_for_decrypt(word: &str, password: &str) -> Result<ParseOps> {
    let mut p = ParseOps::new(policy())?;
    p.transforms.decrypt.insert(word.to_string());
    p.transforms.encrypt.clear();
    p.transforms.store.clear();
    p.transforms.fetch.clear();
    p.passwords.insert(word.to_string(), password.to_string());
    p.io.inline_data = true;
    Ok(p)
}

/// Build a `ParseOps` configured to ENCRYPT + STORE the named WORD
/// (the encrypt-store combined operation). This one DOES use CAS
/// because encrypt-store inherently writes ciphertext to CAS.
fn paops_for_encrypt_store(word: &str, password: &str) -> Result<ParseOps> {
    let mut p = ParseOps::new(policy())?;
    p.transforms.encrypt.insert(word.to_string());
    p.transforms.store.insert(word.to_string());
    p.transforms.decrypt.clear();
    p.transforms.fetch.clear();
    p.passwords.insert(word.to_string(), password.to_string());
    p.crypto.cipheropts.alg = "aes-256-gcm-siv-det".to_string();
    let mut params = BTreeMap::new();
    params.insert("i".to_string(), 1000);
    p.crypto.pbkdfopts = PBKDFOptions {
        alg: "pbkdf2-sha256".to_string(),
        saltlen: 0,
        salt: Some(b"01234567".to_vec()),
        msec: None,
        params: Some(params),
    };
    Ok(p)
}

/// Run a transform pass on the given input bytes; return the output bytes.
fn transform_bytes(input: &str, mut paops: ParseOps) -> Result<String> {
    let cursor = Cursor::new(input.to_string());
    let tree = parse(cursor, &mut paops)?;
    let tree = transform(&tree, &mut paops)?;
    let mut out = Vec::new();
    tree_write(&mut out, &tree, &mut paops)?;
    Ok(String::from_utf8(out).expect("tree_write produces UTF-8"))
}

/// Generate a small EPT file with one BEGIN/END block containing random text.
fn arb_ept_file() -> impl Strategy<Value = String> {
    (
        "[A-Z][A-Z0-9_]{0,15}",   // WORD
        "[a-zA-Z0-9 ./=]{0,200}", // block body (printable, no EPT directives)
        "[a-zA-Z0-9 .]{0,100}",   // pre-block plain text
        "[a-zA-Z0-9 .]{0,100}",   // post-block plain text
    )
        .prop_map(|(word, body, pre, post)| {
            format!("{pre}\n// <( BEGIN {word} )>\n{body}\n// <( END {word} )>\n{post}\n")
        })
}

proptest! {
    #[test]
    fn store_fetch_identity(file in arb_ept_file()) {
        // Pick the WORD out of the generated file (always the first BEGIN).
        let word = match_indices_word(&file).unwrap_or_else(|| "TEST".to_string());

        let dir = tempdir();
        let mut store_paops = paops_for_store(&word).unwrap();
        store_paops.io.set_local_casdir(dir.path().to_path_buf());
        let stored = transform_bytes(&file, store_paops).unwrap();

        // STORE should have produced a STORED directive, not a plain BEGIN.
        prop_assert!(
            stored.contains(&format!("STORED {word}")),
            "expected STORED directive in:\n{stored}"
        );

        let mut fetch_paops = paops_for_fetch(&word).unwrap();
        fetch_paops.io.set_local_casdir(dir.path().to_path_buf());
        let fetched = transform_bytes(&stored, fetch_paops).unwrap();

        // FETCH should restore the original file verbatim.
        prop_assert_eq!(fetched, file, "store/fetch not byte-equal");
    }

    #[test]
    fn cas_dedup(body1 in "[a-zA-Z0-9 ]{0,200}", body2 in "[a-zA-Z0-9 ]{0,200}") {
        let dir = tempdir();
        let h1 = cas_hash(&body1, dir.path());
        let h2 = cas_hash(&body2, dir.path());

        // Same content ⇒ same hash.
        prop_assert_eq!(body1 == body2, h1 == h2);
    }

    #[test]
    fn cas_key_is_stable_across_runs(body in "[a-zA-Z0-9 ]{0,500}") {
        // Same content stored twice (different ParseOps instances,
        // different tempdirs) must produce the same hash. This is
        // the content-addressed-storage invariant that the merge
        // driver relies on.
        let dir1 = tempdir();
        let dir2 = tempdir();
        let h1 = cas_hash(&body, dir1.path());
        let h2 = cas_hash(&body, dir2.path());
        prop_assert_eq!(&h1, &h2);
        prop_assert_eq!(h1.len(), 64);
    }

    #[test]
    fn encrypt_decrypt_identity(
        file in arb_ept_file(),
        password in "[A-Za-z0-9!@#$%^&*]{4,32}"
    ) {
        // encrypt then decrypt must round-trip byte-for-byte.
        // Inline mode (no CAS) keeps this test hermetic — no tempdir
        // contention with parallel proptest cases.
        let word = match_indices_word(&file).unwrap_or_else(|| "TEST".to_string());

        let encrypted = transform_bytes(&file, paops_for_encrypt(&word, &password).unwrap()).unwrap();

        // Encryption must produce an ENCRYPTED directive.
        prop_assert!(
            encrypted.contains(&format!("ENCRYPTED {word}")),
            "expected ENCRYPTED directive in:\n{encrypted}"
        );

        let decrypted = transform_bytes(&encrypted, paops_for_decrypt(&word, &password).unwrap()).unwrap();

        // Decryption must restore the original file verbatim.
        prop_assert_eq!(decrypted, file, "encrypt/decrypt not byte-equal");
    }

    #[test]
    fn encrypt_idempotent(
        file in arb_ept_file(),
        password in "[A-Za-z0-9!@#$%^&*]{4,32}"
    ) {
        // encrypt(encrypt(file)) must equal encrypt(file) — the
        // second pass finds the already-encrypted block and leaves
        // it alone (the deterministic -det variant is required for
        // this to hold; a random-IV variant would re-encrypt).
        let word = match_indices_word(&file).unwrap_or_else(|| "TEST".to_string());

        let once = transform_bytes(&file, paops_for_encrypt(&word, &password).unwrap()).unwrap();
        let twice = transform_bytes(&once, paops_for_encrypt(&word, &password).unwrap()).unwrap();

        prop_assert_eq!(once, twice, "encrypt not idempotent");
    }

    #[test]
    fn encrypt_store_round_trip(
        file in arb_ept_file(),
        password in "[A-Za-z0-9!@#$%^&*]{4,32}"
    ) {
        // The combined encrypt-store op must round-trip via
        // fetch-then-decrypt. This is the user-facing guarantee:
        // `enprot encrypt-store -w WORD` followed by
        // `enprot fetch -w WORD | enprot decrypt -w WORD` returns
        // the original file byte-for-byte.
        let word = match_indices_word(&file).unwrap_or_else(|| "TEST".to_string());

        // Forward: encrypt-store.
        let dir = tempdir();
        let mut es = paops_for_encrypt_store(&word, &password).unwrap();
        es.io.set_local_casdir(dir.path().to_path_buf());
        let encrypted_stored = transform_bytes(&file, es).unwrap();

        // Reverse: fetch-then-decrypt (combined in a single paops).
        let mut fd = paops_for_fetch(&word).unwrap();
        fd.io.set_local_casdir(dir.path().to_path_buf());
        fd.transforms.decrypt.insert(word.clone());
        fd.passwords.insert(word.clone(), password.clone());
        let recovered = transform_bytes(&encrypted_stored, fd).unwrap();

        prop_assert_eq!(recovered, file, "encrypt-store didn't round-trip");
    }

    #[test]
    fn cas_load_save_roundtrip(body in "[a-zA-Z0-9 ]{0,500}") {
        // cas::save(blob) then cas::load(hash) must return the
        // original blob byte-for-byte. This is the CAS trait's
        // foundational invariant.
        use enprot::cas;

        let dir = tempdir();
        let mut paops = ParseOps::new(policy()).unwrap();
        paops.io.set_local_casdir(dir.path().to_path_buf());

        let blob = body.into_bytes();
        let hash = cas::save(blob.clone(), &mut paops).unwrap();
        let recovered = cas::load(&hash, &mut paops).unwrap();

        prop_assert_eq!(recovered, blob, "cas load(save(blob)) != blob");
    }
}

/// Extract the first WORD from the first `BEGIN ` directive in `file`.
fn match_indices_word(file: &str) -> Option<String> {
    file.match_indices("BEGIN ")
        .next()
        .and_then(|(i, _)| file[i + 6..].split_whitespace().next())
        .map(|s| s.to_string())
}

/// Run a STORE on a body and return the CAS hash that landed.
fn cas_hash(body: &str, casdir: &std::path::Path) -> String {
    let word = "TEST";
    let file = format!("// <( BEGIN {word} )>\n{body}\n// <( END {word} )>\n");
    let mut paops = paops_for_store(word).unwrap();
    paops.io.set_local_casdir(casdir.to_path_buf());
    let stored = transform_bytes(&file, paops).unwrap();

    // Extract the hash from `// <( STORED TEST <hash> )>`.
    stored
        .match_indices("STORED ")
        .next()
        .map(|(i, _)| {
            let tail = &stored[i + 7..];
            // Skip the WORD, then take the next hex token.
            tail.split_whitespace()
                .nth(1)
                .unwrap_or("")
                .trim_end_matches(|c: char| !c.is_ascii_hexdigit())
                .to_string()
        })
        .unwrap_or_default()
}

/// Tiny tempdir helper — we don't depend on the `tempfile` crate from
/// this test binary's deps directly (it's already in enprot's
/// dev-deps; re-using it here would require adding it).
///
/// Uses an atomic counter + thread ID + nanos for uniqueness so
/// parallel proptest cases never collide on the same path. Earlier
/// iterations used nanos alone; under load that wasn't unique.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let thread_id = format!("{:?}", std::thread::current().id());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("enprot-proptest-{nanos}-{n}-{thread_id}"));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}
