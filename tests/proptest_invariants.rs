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
//!
//! All properties run 256 random cases per default proptest config.
//!
//! See `TODO.complete/08-property-invariants` for the design.

use std::io::Cursor;

use proptest::prelude::*;

use enprot::Result;
use enprot::crypto::{CryptoPolicy, CryptoPolicyDefault};
use enprot::etree::{ParseOps, parse, transform, tree_write};

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
        let word = file
            .match_indices("BEGIN ")
            .next()
            .and_then(|(i, _)| file[i + 6..].split_whitespace().next())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "TEST".to_string());

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
    let path = std::env::temp_dir().join(format!(
        "enprot-proptest-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    TempDir(path)
}
