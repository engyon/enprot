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

//! Rekor transparency-log layer (TODO.complete/27's remaining
//! backend) — a **wrapper**, not a primary CAS: Rekor stores hashes
//! and signatures, never content, so [`RekorTlog`] delegates storage
//! to an inner backend and appends a `hashedrekord` entry per save.
//!
//! Wire format per save:
//!
//! - `data.hash` = SHA-256 of the blob (Rekor mandates SHA-256 for
//!   hashedrekord; computed via Botan directly because it is
//!   transport encoding, not enprot's crypto posture — the CAS key
//!   stays SHA3-256).
//! - `signature` = Ed25519 over the SHA3-256 CAS key hex — commits
//!   the signer to the blob's enprot identity. Ed25519 is
//!   deterministic, so the exact entry can be rebuilt client-side
//!   and retrieved by value (Rekor has no lookup-by-content-hash).
//!
//! Configuration (env, alongside `--casdir rekor://host:port`):
//!
//! - `ENPROT_REKOR_INNER` — inner CAS spec (path, `memory:`);
//!   default `.`.
//! - `ENPROT_REKOR_SIGNER` — Ed25519 private key PEM path.
//!
//! `verify_inclusion(blob)` rebuilds the entry, retrieves it from
//! the log, and checks the returned inclusion proof's internal hash
//! chain (leaf → root) — the server can't fabricate an entry the
//! client recomputed, and a well-formed chain to the returned root
//! is the transparency property at transport level.

use std::sync::Mutex;

use serde_json::{Value, json};

use super::CasStore;
use crate::crypto;
use crate::error::{Error, Result};
use crate::pki::{self, SigAlgKind};

pub struct RekorTlog {
    inner: Box<dyn CasStore>,
    url: String,
    signer_pem: String,
    rt: Mutex<tokio::runtime::Runtime>,
}

/// What `verify_inclusion` proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekorInclusion {
    pub log_index: u64,
    pub tree_size: u64,
    pub root_hash: String,
}

fn rekor_error(op: &'static str, detail: impl std::fmt::Display) -> Error {
    Error::CasBackend {
        backend: "rekor",
        op,
        detail: detail.to_string(),
    }
}

impl RekorTlog {
    /// Build from `rekor://host:port`. The inner backend and signer
    /// come from `ENPROT_REKOR_INNER` / `ENPROT_REKOR_SIGNER`.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let url = spec
            .trim_start_matches("rekor://")
            .trim_end_matches('/')
            .to_string();
        if url.is_empty() {
            return Err(Error::InvalidArg {
                arg: "--casdir",
                reason: "rekor spec needs a host: rekor://host:port".to_string(),
            });
        }
        let inner_spec = std::env::var("ENPROT_REKOR_INNER").unwrap_or_else(|_| ".".into());
        let inner = super::open_cas(&inner_spec)?;
        let signer_path = std::env::var("ENPROT_REKOR_SIGNER").map_err(|_| Error::InvalidArg {
            arg: "--casdir",
            reason: "rekor CAS needs ENPROT_REKOR_SIGNER=<Ed25519 PRIV.pem>".to_string(),
        })?;
        let signer_pem = std::fs::read_to_string(signer_path)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--casdir",
                reason: format!("cannot start the rekor runtime: {e}"),
            })?;
        Ok(Self {
            inner,
            url: format!("http://{url}"),
            signer_pem,
            rt: Mutex::new(rt),
        })
    }

    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt
            .lock()
            .expect("rekor runtime mutex poisoned")
            .block_on(fut)
    }

    /// SHA-256 hex of the blob. Not routed through the policy layer:
    /// Rekor's hashedrekord format mandates SHA-256; this is the
    /// log's transport encoding, not enprot's content addressing
    /// (which stays SHA3-256 everywhere else).
    fn sha256_hex(blob: &[u8]) -> Result<String> {
        let mut h = botan::HashFunction::new("SHA-256").map_err(Error::botan)?;
        h.update(blob).map_err(Error::botan)?;
        Ok(h.finish()
            .map_err(Error::botan)?
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            }))
    }

    /// Build the hashedrekord entry for a blob whose CAS key is
    /// `cas_key`. Deterministic: Ed25519 signatures are
    /// deterministic, so the same (blob, key) yields the same entry.
    fn build_entry(blob: &[u8], cas_key: &str, signer_pem: &str) -> Result<Value> {
        let sha = Self::sha256_hex(blob)?;
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
        let sig = pki::sign(
            SigAlgKind::Ed25519,
            signer_pem,
            cas_key.as_bytes(),
            &mut rng,
        )?;
        let privkey = botan::Privkey::load_pem(signer_pem).map_err(Error::botan)?;
        let pub_pem = privkey
            .pubkey()
            .map_err(Error::botan)?
            .pem_encode()
            .map_err(Error::botan)?;
        Ok(json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": { "hash": { "algorithm": "sha256", "value": sha } },
                "signature": {
                    "content": crate::utils::base64_encode(&sig)?,
                    "publicKey": { "content": crate::utils::base64_encode(pub_pem.as_bytes())? }
                }
            }
        }))
    }

    /// Append an entry for `blob` to the log. Returns the
    /// server-assigned UUID.
    fn submit(&self, entry: &Value) -> Result<String> {
        let url = format!("{}/api/v1/log/entries", self.url);
        let uuid = self.block_on(async {
            let client = reqwest::Client::new();
            let body = serde_json::to_string(entry).map_err(|e| rekor_error("submit", e))?;
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| rekor_error("submit", e))?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| rekor_error("submit", e))?;
            let body: Value = serde_json::from_str(&text)
                .map_err(|e| rekor_error("submit", format!("invalid response body: {e}")))?;
            if !status.is_success() {
                return Err(rekor_error(
                    "submit",
                    format!(
                        "HTTP {status}: {}",
                        serde_json::to_string(&body).unwrap_or_default()
                    ),
                ));
            }
            // Response: { "<uuid>": { "body": ..., "logIndex": ... } }
            body.as_object()
                .and_then(|o| o.keys().next().cloned())
                .ok_or_else(|| rekor_error("submit", "response carries no entry UUID"))
        })?;
        Ok(uuid)
    }

    /// Rebuild the client-side entry for `blob` and prove it is in
    /// the log: retrieve it by value, then check the inclusion
    /// proof's hash chain from our leaf to the returned root.
    pub fn verify_inclusion(
        &self,
        blob: &[u8],
        policy: &dyn crypto::CryptoPolicy,
    ) -> Result<RekorInclusion> {
        let cas_key = self.inner.save(blob, policy)?; // idempotent; also the signed identity
        let entry = Self::build_entry(blob, &cas_key, &self.signer_pem)?;
        let url = format!("{}/api/v1/log/entries/retrieve", self.url);
        let found = self.block_on(async {
            let client = reqwest::Client::new();
            let body = serde_json::to_string(&json!({ "entries": [entry] }))
                .map_err(|e| rekor_error("verify", e))?;
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| rekor_error("verify", e))?;
            let status = resp.status();
            let text = resp.text().await.map_err(|e| rekor_error("verify", e))?;
            let body: Value = serde_json::from_str(&text)
                .map_err(|e| rekor_error("verify", format!("invalid response body: {e}")))?;
            if status.as_u16() == 404 || status.as_u16() == 422 {
                return Ok(None);
            }
            if !status.is_success() {
                return Err(rekor_error(
                    "verify",
                    format!(
                        "HTTP {status}: {}",
                        serde_json::to_string(&body).unwrap_or_default()
                    ),
                ));
            }
            Ok(body.as_object().and_then(|o| o.values().next().cloned()))
        })?;
        let Some(entry_resp) = found else {
            return Err(rekor_error(
                "verify",
                "entry not found in the transparency log",
            ));
        };
        let verification = entry_resp
            .get("verification")
            .cloned()
            .unwrap_or(Value::Null);
        let (log_index, tree_size, root_hash, proof_hashes) = parse_inclusion(&verification)?;
        let leaf_sha = Self::sha256_hex(blob)?;
        verify_hash_chain(&leaf_sha, log_index, tree_size, &proof_hashes, &root_hash)?;
        Ok(RekorInclusion {
            log_index,
            tree_size,
            root_hash,
        })
    }
}

/// Extract (logIndex, treeSize, rootHash, hashes) from a Rekor
/// verification block.
fn parse_inclusion(v: &Value) -> Result<(u64, u64, String, Vec<String>)> {
    let proof = v.get("inclusionProof").ok_or_else(|| {
        rekor_error(
            "verify",
            "server returned no inclusion proof (proof=true missing?)",
        )
    })?;
    Ok((
        proof.get("logIndex").and_then(|x| x.as_u64()).unwrap_or(0),
        proof
            .get("treeSize")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| rekor_error("verify", "inclusion proof has no treeSize"))?,
        proof
            .get("rootHash")
            .and_then(|x| x.as_str())
            .ok_or_else(|| rekor_error("verify", "inclusion proof has no rootHash"))?
            .to_string(),
        proof
            .get("hashes")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    ))
}

/// RFC 6962-style Merkle path check: fold the leaf hash through the
/// audit path according to the leaf index and tree size, and compare
/// with the root. This proves the returned proof is internally
/// consistent with the returned root — the server cannot fabricate a
/// path that lands on an unrelated root.
pub(crate) fn verify_hash_chain(
    leaf_sha_hex: &str,
    mut index: u64,
    mut tree_size: u64,
    hashes: &[String],
    root_hex: &str,
) -> Result<()> {
    let mut fold = hex::decode(leaf_sha_hex).map_err(Error::from)?;
    let mut last = tree_size.saturating_sub(1);
    for proof_hash in hashes {
        let ph = hex::decode(proof_hash).map_err(Error::from)?;
        let mut buf = Vec::with_capacity(1 + fold.len() + ph.len());
        if index % 2 == 1 || index == last {
            buf.push(0x01);
            buf.extend_from_slice(&ph);
            buf.extend_from_slice(&fold);
        } else {
            buf.push(0x01);
            buf.extend_from_slice(&fold);
            buf.extend_from_slice(&ph);
        }
        let mut h = botan::HashFunction::new("SHA-256").map_err(Error::botan)?;
        h.update(&buf).map_err(Error::botan)?;
        fold = h.finish().map_err(Error::botan)?;
        if index.is_multiple_of(2) {
            let mut next_last = (last + 1).div_ceil(2) - 1;
            while next_last > 0 && index / 2 > next_last {
                next_last = (next_last * 2 + 1).min(last);
            }
            last = next_last;
        }
        index /= 2;
        tree_size /= 2;
        let _ = tree_size;
    }
    let computed = fold.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    if computed != root_hex.to_lowercase() {
        return Err(rekor_error(
            "verify",
            format!(
                "inclusion proof chain does not reach the root: computed {computed}, root {root_hex}"
            ),
        ));
    }
    Ok(())
}

impl CasStore for RekorTlog {
    fn name(&self) -> &'static str {
        "rekor"
    }

    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
        let cas_key = self.inner.save(blob, policy)?;
        let entry = Self::build_entry(blob, &cas_key, &self.signer_pem)?;
        self.submit(&entry)?;
        Ok(cas_key)
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        self.inner.load(hash, policy)
    }

    fn contains(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        self.inner.contains(hash, policy)
    }

    fn list(&self) -> Result<Vec<String>> {
        self.inner.list()
    }

    fn delete(&self, hash: &str) -> Result<()> {
        self.inner.delete(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_proof_reaches_root() {
        // One-entry tree: the audit path is empty and the root IS the
        // leaf hash (post-leaf-hash).
        let leaf = "aa".repeat(32);
        assert!(verify_hash_chain(&leaf, 0, 1, &[], &leaf).is_ok());
        assert!(verify_hash_chain(&leaf, 0, 1, &[], &("bb".repeat(32))).is_err());
    }

    #[test]
    fn two_leaf_proof_reaches_root() {
        // Tree of two leaves: root = H(0x01 || L0 || L1).
        let l0 = "11".repeat(32);
        let l1 = "22".repeat(32);
        let mut h = botan::HashFunction::new("SHA-256").unwrap();
        h.update(&[0x01]).unwrap();
        h.update(&hex::decode(&l0).unwrap()).unwrap();
        h.update(&hex::decode(&l1).unwrap()).unwrap();
        let root_hex: String = h.finish().unwrap().iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert!(verify_hash_chain(&l0, 0, 2, std::slice::from_ref(&l1), &root_hex).is_ok());
        assert!(verify_hash_chain(&l1, 1, 2, std::slice::from_ref(&l0), &root_hex).is_ok());
        // A wrong path must not reach the root.
        assert!(verify_hash_chain(&l0, 0, 2, std::slice::from_ref(&l0), &root_hex).is_err());
    }

    #[test]
    fn entry_is_deterministic() {
        let policy = crypto::default_policy();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let (priv_pem, _) = pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap();
        let a = RekorTlog::build_entry(b"blob", "cafe", &priv_pem).unwrap();
        let b = RekorTlog::build_entry(b"blob", "cafe", &priv_pem).unwrap();
        assert_eq!(a, b, "same (blob, key) must rebuild the same entry");
        let _ = &*policy;
    }

    // from_spec with no signer configured must fail with the env
    // var's name. Env manipulation is unsafe in edition 2024 — tested
    // through a subprocess-style isolation instead: build the spec
    // error path directly by checking the env BEFORE set_var is ever
    // needed. The unit here covers the empty-host guard only.
    #[test]
    fn rekor_spec_requires_host() {
        let err = match RekorTlog::from_spec("rekor://") {
            Err(e) => e,
            Ok(_) => panic!("from_spec must fail on an empty host"),
        };
        assert!(err.to_string().contains("host"));
    }
}
