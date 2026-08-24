//! IPFS-backed content-addressed storage (TODO.complete/27).
//!
//! `ipfs://host:port` speaks the Kubo HTTP RPC (`/api/v0/…`) over
//! reqwest. No gateway fetches, no swarm dialing — the node you
//! point at owns pinning and retrieval.
//!
//! The naming insight that keeps this backend table-free: enprot
//! names blobs by SHA3-256, and **CIDv1 with the raw codec and the
//! sha3-256 multihash is a pure encoding of that same digest**:
//!
//! ```text
//! hash (64 hex) ──► digest(32B) ──► multihash(0x16 ‖ len ‖ digest)
//!                ──► CIDv1(0x01 ‖ 0x55 ‖ multihash) ──► base32 'b'
//! ```
//!
//! so `cid_for(hash)` and `hash_for(cid)` are local functions, and
//! `save`/`load` simply re-encode. A malformed CID (wrong codec,
//! wrong hash function) is rejected rather than mapped — the CAS
//! contract is SHA3-256 end to end.
//!
//! Saves pin (`/add?pin=1`) so the node retains the blob beyond
//! GC; `list` enumerates pins and filters to raw/sha3-256 CIDs.
//! Unlike the S3 backend there is no async bridge at all — blocking
//! reqwest covers the whole RPC surface. Every load re-hashes and
//! compares before returning bytes.

use cid::Cid;
use cid::multihash::Multihash;
use multibase::Base;

use crate::crypto;
use crate::error::{Error, Result};

use super::CasStore;

#[derive(Debug)]
pub struct IpfsCas {
    api: reqwest::blocking::Client,
    base: String,
}

impl IpfsCas {
    /// Build from an `ipfs://host:port` spec (the Kubo RPC endpoint;
    /// port defaults to 5001). Plain HTTP is accepted deliberately —
    /// most nodes are loopback; TLS endpoints use ipfs://https://…
    /// style URLs via `Url` parsing below.
    pub fn from_spec(spec: &str) -> Result<Self> {
        let rest = spec
            .strip_prefix("ipfs://")
            .ok_or_else(|| Error::InvalidArg {
                arg: "--casdir",
                reason: format!("IPFS CAS spec must start with ipfs://, got '{spec}'"),
            })?;
        if rest.is_empty() {
            return Err(Error::InvalidArg {
                arg: "--casdir",
                reason: "IPFS CAS spec needs a host, e.g. ipfs://localhost:5001".into(),
            });
        }
        // A scheme inside the rest (ipfs://https://gw.example) keeps
        // its TLS form; otherwise this is host[:port] over http.
        let (scheme, authority) = if rest.contains("://") {
            let (s, r) = rest.split_once("://").expect("checked");
            (s.to_string(), r.to_string())
        } else {
            ("http".to_string(), rest.to_string())
        };
        let authority = authority.trim_end_matches('/');
        let base = format!("{scheme}://{authority}");
        // Probe-shape validation only; real reachability surfaces on
        // first use with a precise error.
        let api = reqwest::blocking::Client::builder()
            .build()
            .map_err(|e| Error::InvalidArg {
                arg: "--casdir",
                reason: format!("cannot build IPFS client: {e}"),
            })?;
        Ok(Self { api, base })
    }

    fn rpc_error(&self, op: &'static str, e: reqwest::Error) -> Error {
        Error::CasBackend {
            backend: "ipfs",
            op,
            detail: e.to_string(),
        }
    }
}

/// SHA3-256 digest hex → CIDv1 (raw codec, sha3-256 multihash, base32).
pub fn cid_for_hash(hash: &str) -> Result<String> {
    super::validate_cas_hash(hash)?;
    let digest = hex::decode(hash).map_err(|_| Error::CasHashInvalid { hash: hash.into() })?;
    let mh = Multihash::<64>::wrap(0x16, &digest).expect("sha3-256 digest is 32 bytes");
    let cid = Cid::new_v1(0x55, mh);
    Ok(cid
        .to_string_of_base(Base::Base32Lower)
        .expect("base32 of a v1 CID"))
}

/// CID (any multibase) → SHA3-256 hex; rejects non-raw codecs and
/// non-sha3 multihashes — this CAS only speaks its own namespace.
pub fn hash_for_cid(cid: &str) -> Result<String> {
    let cid = Cid::try_from(cid.to_string()).map_err(|e| Error::CasHashInvalid {
        hash: format!("not a CID: {e}"),
    })?;
    if cid.codec() != 0x55 {
        return Err(Error::CasHashInvalid {
            hash: format!("CID codec {:#x} is not raw (0x55)", cid.codec()),
        });
    }
    let mh = cid.hash();
    if mh.code() != 0x16 {
        return Err(Error::CasHashInvalid {
            hash: format!("CID multihash {:#x} is not sha3-256 (0x16)", mh.code()),
        });
    }
    let hex = hex::encode(mh.digest());
    super::validate_cas_hash(&hex)?;
    Ok(hex)
}

impl CasStore for IpfsCas {
    fn name(&self) -> &'static str {
        "ipfs"
    }

    fn save(&self, blob: &[u8], policy: &dyn crypto::CryptoPolicy) -> Result<String> {
        let hash = crypto::hexdigest("sha3-256", blob, policy)?;
        let cid = cid_for_hash(&hash)?;
        let part = reqwest::blocking::multipart::Part::bytes(blob.to_vec()).file_name(hash.clone());
        let form = reqwest::blocking::multipart::Form::new().part("file", part);
        let resp = self
            .api
            .post(format!("{}/api/v0/add?pin=true&cid-version=1", self.base))
            .multipart(form)
            .send()
            .map_err(|e| self.rpc_error("add", e))?;
        if !resp.status().is_success() {
            return Err(Error::CasBackend {
                backend: "ipfs",
                op: "add",
                detail: format!("HTTP {}", resp.status()),
            });
        }
        // The node computed its own CID; it must equal ours or the
        // content/naming contract is broken (wrong hash function,
        // codec drift, truncated upload).
        let body = resp.text().map_err(|e| self.rpc_error("add (read)", e))?;
        let returned = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("Hash").and_then(|h| h.as_str()).map(String::from));
        match returned {
            Some(r) if hash_for_cid(&r)? == hash => Ok(hash),
            Some(r) => Err(Error::CasHashMismatch {
                expected: cid,
                actual: r,
            }),
            None => Err(Error::CasBackend {
                backend: "ipfs",
                op: "add",
                detail: format!("unparseable response: {body}"),
            }),
        }
    }

    fn load(&self, hash: &str, policy: &dyn crypto::CryptoPolicy) -> Result<Vec<u8>> {
        super::validate_cas_hash(hash)?;
        let cid = cid_for_hash(hash)?;
        let resp = self
            .api
            .post(format!("{}/api/v0/cat?arg={cid}", self.base))
            .send()
            .map_err(|e| self.rpc_error("cat", e))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND
            || resp.status() == reqwest::StatusCode::BAD_REQUEST
        {
            // Kubo answers 500 with "ipld: could not find" for absent
            // blocks on some versions; treat both non-success shapes
            // that mention absence as NotFound.
            let body = resp.text().unwrap_or_default();
            if body.contains("could not find") || body.contains("not found") {
                return Err(Error::CasNotFound { hash: hash.into() });
            }
            return Err(Error::CasBackend {
                backend: "ipfs",
                op: "cat",
                detail: format!("HTTP {body}"),
            });
        }
        let bytes = resp
            .bytes()
            .map_err(|e| self.rpc_error("cat (read body)", e))?
            .to_vec();
        let actual = crypto::hexdigest("sha3-256", &bytes, policy)?;
        if actual != hash {
            return Err(Error::CasHashMismatch {
                expected: hash.into(),
                actual,
            });
        }
        Ok(bytes)
    }

    fn contains(&self, hash: &str, _policy: &dyn crypto::CryptoPolicy) -> Result<bool> {
        super::validate_cas_hash(hash)?;
        let cid = cid_for_hash(hash)?;
        let resp = self
            .api
            .post(format!(
                "{}/api/v0/pin/ls?arg={cid}&type=recursive",
                self.base
            ))
            .send()
            .map_err(|e| self.rpc_error("pin/ls", e))?;
        if resp.status().is_success() {
            return Ok(true);
        }
        let body = resp.text().unwrap_or_default();
        if body.contains("not pinned") || body.contains("not found") {
            return Ok(false);
        }
        Err(Error::CasBackend {
            backend: "ipfs",
            op: "pin/ls",
            detail: body,
        })
    }

    fn list(&self) -> Result<Vec<String>> {
        let resp = self
            .api
            .post(format!("{}/api/v0/pin/ls?type=recursive", self.base))
            .send()
            .map_err(|e| self.rpc_error("pin/ls", e))?;
        if !resp.status().is_success() {
            return Err(Error::CasBackend {
                backend: "ipfs",
                op: "pin/ls",
                detail: format!("HTTP {}", resp.status()),
            });
        }
        let body = resp
            .text()
            .map_err(|e| self.rpc_error("pin/ls (read)", e))?;
        // Keys map cid → pin metadata; entries may be NDJSON lines on
        // streaming endpoints. Collect every raw/sha3-256 CID.
        let mut hashes = Vec::new();
        for line in body.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(keys) = v.get("Keys").and_then(|k| k.as_object()) else {
                continue;
            };
            for cid_str in keys.keys() {
                if let Ok(h) = hash_for_cid(cid_str) {
                    hashes.push(h);
                }
            }
        }
        hashes.sort();
        hashes.dedup();
        Ok(hashes)
    }

    fn delete(&self, hash: &str) -> Result<()> {
        super::validate_cas_hash(hash)?;
        let cid = cid_for_hash(hash)?;
        let resp = self
            .api
            .post(format!("{}/api/v0/pin/rm?arg={cid}", self.base))
            .send()
            .map_err(|e| self.rpc_error("pin/rm", e))?;
        if !resp.status().is_success() {
            return Err(Error::CasBackend {
                backend: "ipfs",
                op: "pin/rm",
                detail: format!("HTTP {}", resp.status()),
            });
        }
        Ok(())
    }
}
