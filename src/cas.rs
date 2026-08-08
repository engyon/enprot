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
// SPECIAL, CONSEQUENTIAL, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Content-addressed storage (CAS).
//!
//! Per TODO.completion/15: the storage backend is now a trait so
//! consumers can plug in S3 / IPFS / git-lfs / in-memory stores
//! without forking enprot. The default backend is [`LocalCas`],
//! rooted at `ParseOps.io.casdir`.
//!
//! Hash algorithm: SHA3-256 (enprot's CAS default). The hash is
//! content-derived, so non-constant-time comparison is safe (a
//! timing leak only reveals how many leading hex chars of a public
//! hash match; no secret material is exposed).

use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::crypto;
use crate::error::{Error, Result};
use crate::etree::ParseOps;

/// Pluggable content-addressed storage. The trait abstracts over
/// local disk, S3, IPFS, in-memory, etc. Implementations must be
/// idempotent — saving the same blob twice returns the same hash
/// with no side effect on the second call.
///
/// All hashes are SHA3-256 hex strings of length 64. Backends that
/// use other hash algorithms internally must map to/from SHA3-256.
pub trait CasStore: Send + Sync {
    /// Save a blob, return its content hash. Idempotent.
    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String>;

    /// Load a blob by hash. Errors if not present or hash doesn't
    /// match content (the verification is the backend's job — a
    /// content-addressed store MUST verify on read).
    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>>;

    /// Check existence without loading. Default: try load and
    /// discard. Backends with cheaper existence checks should override.
    fn contains(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        Ok(self.load(hash, policy).is_ok())
    }

    /// Enumerate all blob hashes in the store. Used by `cas gc` to
    /// identify orphans. Backends that can't enumerate (e.g.,
    /// append-only transparency logs) should leave the default.
    fn list(&self) -> Result<Vec<String>> {
        Err(Error::CasUnsupported { op: "list" })
    }

    /// Delete a blob by hash. Used by `cas gc` to reclaim space.
    /// Backends that don't support deletion should leave the default.
    fn delete(&self, _hash: &str) -> Result<()> {
        Err(Error::CasUnsupported { op: "delete" })
    }
}

/// Filesystem-backed CAS. The default; replaces the old
/// `cas::save`/`cas::load` free functions.
pub struct LocalCas {
    pub root: PathBuf,
    pub verbose: bool,
}

impl LocalCas {
    pub fn new(root: PathBuf) -> Self {
        LocalCas {
            root,
            verbose: false,
        }
    }

    fn path_for(&self, hash: &str) -> PathBuf {
        self.root.join(hash)
    }
}

impl CasStore for LocalCas {
    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
        let hexhash = crypto::hexdigest("sha3-256", blob, policy)?;
        let path = self.path_for(&hexhash);

        if path.is_file() {
            if self.verbose {
                eprintln!("cas::save(): {} already exists. Exiting.", path.display());
            }
            return Ok(hexhash);
        }

        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(blob)?;
            f.sync_all()?;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }

        if self.verbose {
            eprintln!("cas::save(): {} bytes to {}", blob.len(), path.display());
        }
        Ok(hexhash)
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        hex::decode(hash).map_err(|_| Error::CasHashInvalid {
            hash: hash.to_string(),
        })?;
        let path = self.path_for(hash);

        let mut file_in = File::open(&path)?;
        let mut blob = Vec::new();
        let bytes = file_in.read_to_end(&mut blob)?;
        if self.verbose {
            eprintln!("cas::load(): {} bytes from {}", bytes, path.display());
        }

        let verify = crypto::hexdigest("sha3-256", &blob, policy)?;
        if hash != verify {
            return Err(Error::CasHashMismatch {
                expected: hash.to_string(),
                actual: verify,
            });
        }
        Ok(blob)
    }

    fn list(&self) -> Result<Vec<String>> {
        let read = std::fs::read_dir(&self.root)?;
        let mut hashes = Vec::new();
        for entry in read {
            let entry = entry?;
            let fname = entry.file_name();
            let Some(name) = fname.to_str() else {
                continue;
            };
            if name.len() == 64 && name.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
                hashes.push(name.to_string());
            }
        }
        Ok(hashes)
    }

    fn delete(&self, hash: &str) -> Result<()> {
        hex::decode(hash).map_err(|_| Error::CasHashInvalid {
            hash: hash.to_string(),
        })?;
        let path = self.path_for(hash);
        std::fs::remove_file(&path)?;
        Ok(())
    }
}

/// In-memory CAS for tests + library consumers that don't want
/// filesystem side effects. Backed by a `BTreeMap` under a `RwLock`.
pub struct MemoryCas {
    entries: RwLock<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl MemoryCas {
    pub fn new() -> Self {
        MemoryCas {
            entries: RwLock::new(std::collections::BTreeMap::new()),
        }
    }
}

impl Default for MemoryCas {
    fn default() -> Self {
        Self::new()
    }
}

impl CasStore for MemoryCas {
    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
        let hexhash = crypto::hexdigest("sha3-256", blob, policy)?;
        let mut map = self.entries.write().unwrap();
        map.entry(hexhash.clone()).or_insert_with(|| blob.to_vec());
        Ok(hexhash)
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        let map = self.entries.read().unwrap();
        let blob = map
            .get(hash)
            .ok_or_else(|| Error::CasNotFound {
                hash: hash.to_string(),
            })?
            .clone();
        let verify = crypto::hexdigest("sha3-256", &blob, policy)?;
        if hash != verify {
            return Err(Error::CasHashMismatch {
                expected: hash.to_string(),
                actual: verify,
            });
        }
        Ok(blob)
    }

    fn contains(&self, _hash: &str, _policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        Ok(self.entries.read().unwrap().contains_key(_hash))
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.entries.read().unwrap().keys().cloned().collect())
    }

    fn delete(&self, hash: &str) -> Result<()> {
        self.entries.write().unwrap().remove(hash);
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Free-function wrappers for backward compatibility. Existing callers
// (`cas::save(blob, paops)`) keep working; they dispatch through the
// ParseOps-owned `CasStore` impl. New callers should call the trait
// methods directly on `paops.io.cas`.
// ---------------------------------------------------------------------

#[tracing::instrument(skip(paops), fields(hash = %hexhash))]
pub fn load(hexhash: &str, paops: &mut ParseOps) -> Result<Vec<u8>> {
    let policy: &dyn crypto::CryptoPolicy = &*paops.crypto.policy;
    paops.io.cas.load(hexhash, policy)
}

#[tracing::instrument(skip(blob, paops), fields(bytes = blob.len()))]
pub fn save(blob: Vec<u8>, paops: &mut ParseOps) -> Result<String> {
    let policy: &dyn crypto::CryptoPolicy = &*paops.crypto.policy;
    let hash = paops.io.cas.save(&blob, policy);
    tracing::Span::current().record(
        "hash",
        tracing::field::display(hash.as_ref().map(|h| h.as_str()).unwrap_or("?")),
    );
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::default_policy;

    #[test]
    fn local_cas_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        let blob = b"hello, world";
        let h = store.save(blob, &*policy).unwrap();
        assert_eq!(h.len(), 64);

        let loaded = store.load(&h, &*policy).unwrap();
        assert_eq!(loaded, blob);

        assert!(store.contains(&h, &*policy).unwrap());
        assert!(!store.contains("0".repeat(64).as_str(), &*policy).unwrap());
    }

    #[test]
    fn local_cas_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        let blob = b"same content";
        let h1 = store.save(blob, &*policy).unwrap();
        let h2 = store.save(blob, &*policy).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn local_cas_detects_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        // Write a file with a wrong hash name directly to the dir
        let bad_hash = "0".repeat(64);
        std::fs::write(dir.path().join(&bad_hash), b"unrelated content").unwrap();

        let err = store.load(&bad_hash, &*policy);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("hash mismatch"), "msg: {msg}");
    }

    #[test]
    fn memory_cas_round_trip() {
        let store = MemoryCas::new();
        let policy = default_policy();

        let blob = b"in-memory blob";
        let h = store.save(blob, &*policy).unwrap();
        let loaded = store.load(&h, &*policy).unwrap();
        assert_eq!(loaded, blob);
        assert!(store.contains(&h, &*policy).unwrap());
    }

    #[test]
    fn memory_cas_idempotent() {
        let store = MemoryCas::new();
        let policy = default_policy();

        let blob = b"x";
        let h1 = store.save(blob, &*policy).unwrap();
        let h2 = store.save(blob, &*policy).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn local_cas_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        let h1 = store.save(b"blob one", &*policy).unwrap();
        let h2 = store.save(b"blob two", &*policy).unwrap();

        let mut listed = store.list().unwrap();
        listed.sort();
        let mut expected = vec![h1, h2];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn local_cas_list_ignores_non_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        store.save(b"real blob", &*policy).unwrap();
        std::fs::write(dir.path().join("README.txt"), b"not a blob").unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn local_cas_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        let h = store.save(b"deletable", &*policy).unwrap();
        assert!(store.contains(&h, &*policy).unwrap());

        store.delete(&h).unwrap();
        assert!(!store.contains(&h, &*policy).unwrap());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn local_cas_no_temp_files_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalCas::new(dir.path().to_path_buf());
        let policy = default_policy();

        store.save(b"atomic write test", &*policy).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1, "temp file left behind after save");
    }

    #[test]
    fn memory_cas_list_and_delete() {
        let store = MemoryCas::new();
        let policy = default_policy();

        let h1 = store.save(b"a", &*policy).unwrap();
        let h2 = store.save(b"b", &*policy).unwrap();

        let mut listed = store.list().unwrap();
        listed.sort();
        assert_eq!(listed, vec![h1.clone(), h2.clone()]);

        store.delete(&h1).unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed, vec![h2]);
    }
}

// ---------------------------------------------------------------------------
// CAS backend dispatch (TODO.complete/06-cas-backends).
//
// Entry point for multi-backend CAS selection. Working backends:
// `local:` (filesystem) and `memory:` (in-process). Cloud backends
// (S3, IPFS, Rekor) require their respective cargo features.
// ---------------------------------------------------------------------------

/// Dispatch a CAS specification string into a concrete backend.
///
/// Recognized schemes:
/// - No scheme (bare path): `LocalCas` at that directory.
/// - `memory:`: in-process `MemoryCas` (for testing, ephemeral sessions).
/// - `s3://bucket/prefix`: S3-backed CAS (requires `s3` cargo feature).
/// - `ipfs://gateway`: IPFS-backed CAS (requires `ipfs` cargo feature).
/// - `rekor:`: Rekor transparency-log CAS (requires `sigstore` cargo feature).
pub fn open_cas(spec: &str) -> Result<Box<dyn CasStore>> {
    if spec == "memory:" || spec == "memory" {
        return Ok(Box::new(MemoryCas::new()));
    }
    if spec.starts_with("s3://") {
        return Err(crate::error::Error::Cas("S3 CAS requires --features s3 (not yet built); use 'memory:' for testing or a local path".to_string()));
    }
    if spec.starts_with("ipfs://") {
        return Err(crate::error::Error::Cas("IPFS CAS requires --features ipfs (not yet built); use 'memory:' for testing or a local path".to_string()));
    }
    if spec == "rekor:" || spec.starts_with("rekor://") {
        return Err(crate::error::Error::Cas(
            "Rekor CAS requires --features sigstore (not yet built); use 'memory:' for testing or a local path".into(),
        ));
    }
    // Default: treat as local filesystem path.
    Ok(Box::new(LocalCas {
        root: PathBuf::from(spec),
        verbose: false,
    }))
}

#[cfg(test)]
mod backend_tests {
    use super::*;

    #[test]
    fn open_cas_local_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_cas(dir.path().to_str().unwrap()).unwrap();
        let policy = crate::crypto::default_policy();
        let h = store.save(b"hello", &*policy).unwrap();
        assert_eq!(h.len(), 64);
        let loaded = store.load(&h, &*policy).unwrap();
        assert_eq!(loaded, b"hello");
    }

    #[test]
    fn open_cas_memory_round_trip() {
        let store = open_cas("memory:").unwrap();
        let policy = crate::crypto::default_policy();
        let h = store.save(b"in-memory blob", &*policy).unwrap();
        assert_eq!(h.len(), 64);
        let loaded = store.load(&h, &*policy).unwrap();
        assert_eq!(loaded, b"in-memory blob");
        assert!(store.contains(&h, &*policy).unwrap());
    }

    #[test]
    fn open_cas_s3_returns_actionable_error() {
        match open_cas("s3://my-bucket/cas/") {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("requires --features s3"), "msg: {msg}");
                assert!(
                    msg.contains("memory:"),
                    "should suggest memory: alternative: {msg}"
                );
            }
            Ok(_) => panic!("S3 backend should not be available without --features s3"),
        }
    }

    #[test]
    fn open_cas_rekor_returns_actionable_error() {
        match open_cas("rekor:") {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("requires --features sigstore"), "msg: {msg}");
            }
            Ok(_) => panic!("Rekor backend should not be available without --features sigstore"),
        }
    }
}
