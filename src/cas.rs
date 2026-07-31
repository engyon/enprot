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

        let mut file_out = File::create(&path)
            .map_err(|e| Error::Cas(format!("Failed to open {}: {}", path.display(), e)))?;
        let bytes = file_out.write(blob).map_err(|e| {
            Error::Cas(format!(
                "Error writing {} bytes to {}: {}",
                blob.len(),
                path.display(),
                e
            ))
        })?;
        if self.verbose {
            eprintln!("cas::save(): {} bytes to {}", bytes, path.display());
        }
        Ok(hexhash)
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        hex::decode(hash).map_err(|_| Error::Cas(format!("Not a valid hex token: {}", hash)))?;
        let path = self.path_for(hash);

        let mut file_in = File::open(&path)
            .map_err(|e| Error::Cas(format!("Failed to open {}: {}", path.display(), e)))?;
        let mut blob = Vec::new();
        let bytes = file_in
            .read_to_end(&mut blob)
            .map_err(|e| Error::Cas(format!("Error reading {}: {}", path.display(), e)))?;
        if self.verbose {
            eprintln!("cas::load(): {} bytes from {}", bytes, path.display());
        }

        let verify = crypto::hexdigest("sha3-256", &blob, policy)?;
        if hash != verify {
            return Err(Error::Cas(format!(
                "CONTENT HASH MISMATCH!\ninput = {}\ncheck = {}",
                hash, verify
            )));
        }
        Ok(blob)
    }
}

/// In-memory CAS for tests + library consumers that don't want
/// filesystem side effects. Backed by a `BTreeMap` under a `RwLock`.
#[allow(dead_code)]
pub struct MemoryCas {
    entries: RwLock<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl MemoryCas {
    #[allow(dead_code)]
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
            .ok_or_else(|| Error::Cas(format!("hash not present in memory CAS: {}", hash)))?
            .clone();
        let verify = crypto::hexdigest("sha3-256", &blob, policy)?;
        if hash != verify {
            return Err(Error::Cas(format!(
                "CONTENT HASH MISMATCH (memory)!\ninput = {}\ncheck = {}",
                hash, verify
            )));
        }
        Ok(blob)
    }

    fn contains(&self, _hash: &str, _policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        Ok(self.entries.read().unwrap().contains_key(_hash))
    }
}

// ---------------------------------------------------------------------
// Free-function wrappers for backward compatibility. Existing callers
// (`cas::save(blob, paops)`) keep working; they dispatch through the
// ParseOps-owned `CasStore` impl. New callers should call the trait
// methods directly on `paops.io.cas`.
// ---------------------------------------------------------------------

pub fn load(hexhash: &str, paops: &mut ParseOps) -> Result<Vec<u8>> {
    let policy: &dyn crypto::CryptoPolicy = &*paops.crypto.policy;
    paops.io.cas.load(hexhash, policy)
}

pub fn save(blob: Vec<u8>, paops: &mut ParseOps) -> Result<String> {
    let policy: &dyn crypto::CryptoPolicy = &*paops.crypto.policy;
    paops.io.cas.save(&blob, policy)
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
        assert!(msg.contains("HASH MISMATCH"), "msg: {msg}");
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
}

// ---------------------------------------------------------------------------
// CAS backend dispatch (TODO.complete/06-cas-backends).
//
// The enum below is the entry point for multi-backend CAS selection.
// Callers pass a URL-like spec (e.g., "s3://bucket/prefix",
// "rekor:", "/local/path") and receive a boxed `CasStore`. Today only
// `LocalCas` is implemented; S3 / IPFS / Rekor are stubs that return
// a clear "not yet implemented" error.
// ---------------------------------------------------------------------------

/// Dispatch a CAS specification string into a concrete backend.
///
/// Recognized schemes:
/// - No scheme (bare path): `LocalCas` at that directory.
/// - `s3://bucket/prefix`: S3-backed CAS (TODO: not yet implemented).
/// - `ipfs://gateway`: IPFS-backed CAS (TODO: not yet implemented).
/// - `rekor:`: Rekor transparency-log CAS (TODO: gated on #03 Sigstore).
pub fn open_cas(spec: &str) -> Result<Box<dyn CasStore>> {
    if let Some(rest) = spec.strip_prefix("s3://") {
        return Err(crate::error::Error::msg(format!(
            "S3 CAS backend not yet implemented (spec: s3://{rest}); see TODO.complete/06"
        )));
    }
    if let Some(rest) = spec.strip_prefix("ipfs://") {
        return Err(crate::error::Error::msg(format!(
            "IPFS CAS backend not yet implemented (spec: ipfs://{rest}); see TODO.complete/06"
        )));
    }
    if spec == "rekor:" || spec.starts_with("rekor://") {
        return Err(crate::error::Error::msg(
            "Rekor CAS backend not yet implemented; see TODO.complete/06 (gated on #03 Sigstore)",
        ));
    }
    // Default: treat as local path.
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
    fn open_cas_s3_not_yet_implemented() {
        match open_cas("s3://my-bucket/cas/") {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("not yet implemented"), "msg: {msg}");
                assert!(msg.contains("TODO.complete/06"), "msg: {msg}");
            }
            Ok(_) => panic!("S3 backend should not be available yet"),
        }
    }

    #[test]
    fn open_cas_rekor_not_yet_implemented() {
        match open_cas("rekor:") {
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("not yet implemented"), "msg: {msg}");
            }
            Ok(_) => panic!("Rekor backend should not be available yet"),
        }
    }
}
