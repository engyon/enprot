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

//! [`Anchor`] — one node in the chain anchor DAG.

use std::fmt;
use std::str::FromStr;

use crate::capability::KeyFp;
use crate::error::{Error, Result};
use crate::pki::{self, SigAlgKind};

/// SHA3-256 hash of an anchor's canonical serialization (the
/// `parents || signer || timestamp || payload-hash` byte sequence
/// that the signature commits to). Used as the DAG node identity
/// and as a parent reference from later anchors.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct AnchorHash(pub [u8; 32]);

impl AnchorHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 64-character lowercase hex string. Mirrors `Display`
    /// so round-trips are stable.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::msg(format!(
                "anchor hash must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(AnchorHash(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AnchorHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Hash of the file-tree state at this anchor. The signature commits
/// to this hash, not the file contents directly — so verifiers can
/// re-derive it from a snapshot without re-reading the whole file.
///
/// Same wire format as [`AnchorHash`] (SHA3-256 hex).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct PayloadHash(pub [u8; 32]);

impl PayloadHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(PayloadHash(AnchorHash::from_hex(s)?.0))
    }
}

impl fmt::Display for PayloadHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Identifier for a signing key: `<alg>:<fingerprint-hex>`. Stored in
/// the wire format so verifiers know which algorithm and key to use.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignerId {
    pub alg: SigAlgKind,
    pub fp: KeyFp,
}

impl SignerId {
    pub fn new(alg: SigAlgKind, fp: KeyFp) -> Self {
        SignerId { alg, fp }
    }
}

impl fmt::Display for SignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg, self.fp)
    }
}

impl FromStr for SignerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (alg_str, fp_str) = s.split_once(':').ok_or_else(|| {
            Error::msg(format!(
                "malformed signer id '{}', expected '<alg>:<fp>'",
                s
            ))
        })?;
        let alg: SigAlgKind = alg_str.parse()?;
        let fp_bytes = hex::decode(fp_str)?;
        if fp_bytes.len() != 32 {
            return Err(Error::msg(format!(
                "signer fingerprint must be 32 bytes, got {}",
                fp_bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&fp_bytes);
        Ok(SignerId {
            alg,
            fp: KeyFp::from_bytes(arr),
        })
    }
}

/// An unsigned anchor: the metadata a signer commits to. Once signed,
/// it becomes a [`SignedAnchor`] carrying the signature bytes.
///
/// Field ordering follows the wire format (see `display_unsigned`):
/// parents, signer, timestamp, mutations, payload-hash. The signature
/// commits to `parents || signer || timestamp || payload-hash` (the
/// mutations field is informational, not signed, so it can be edited
/// later for translation/clarity without invalidating the signature).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    /// SHA3-256 hashes of preceding anchors this one builds on.
    /// Genesis anchor has zero parents. Merge anchor has 2+.
    pub parents: Vec<AnchorHash>,

    /// Who signed this anchor and with what algorithm.
    pub signer: SignerId,

    /// RFC 3339 timestamp (e.g., `2026-07-25T14:30:00Z`). Optional —
    /// omitted on genesis or in tests.
    pub timestamp: Option<String>,

    /// Human-readable description of what this anchor attests
    /// (e.g., `encrypt WORD=Agent_007`). Informational; not signed.
    pub mutations: String,

    /// SHA3-256 of the file-tree state at this anchor. The signed
    /// payload commits to this hash.
    pub payload_hash: PayloadHash,
}

impl Anchor {
    /// Builder entry point. Required fields only; optional fields
    /// (`timestamp`, `mutations`) chain-set on the builder.
    pub fn builder(signer: SignerId, payload_hash: PayloadHash) -> AnchorBuilder {
        AnchorBuilder {
            parents: Vec::new(),
            signer,
            timestamp: None,
            mutations: String::new(),
            payload_hash,
        }
    }

    /// Canonical byte sequence the signature commits to. Stable across
    /// implementations; verifiers re-derive this and check the
    /// signature against it.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for p in &self.parents {
            out.extend_from_slice(p.as_bytes());
        }
        // signer canonicalization: "<alg>:<fp-hex>"
        out.extend_from_slice(self.signer.to_string().as_bytes());
        if let Some(ref ts) = self.timestamp {
            out.extend_from_slice(ts.as_bytes());
        }
        out.extend_from_slice(self.payload_hash.0.as_slice());
        out
    }

    /// Compute this anchor's [`AnchorHash`] — SHA3-256 over the
    /// signing bytes plus the (unsigned) mutations, so two anchors
    /// with identical signing bytes but different mutations get
    /// different DAG identities.
    pub fn id(&self) -> Result<AnchorHash> {
        let policy = crate::crypto::CryptoPolicyDefault {};
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(self.mutations.as_bytes());
        let hex = crate::crypto::hexdigest("sha3-256", &bytes, &policy)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hex::decode(hex)?);
        Ok(AnchorHash(arr))
    }

    /// Sign with the caller's private key. Returns a [`SignedAnchor`]
    /// carrying the signature.
    ///
    /// `pubkey_pem` is required to compute the signer fingerprint
    /// (cross-check against `self.signer.fp`) and is checked here so
    /// callers can't accidentally sign under the wrong identity.
    pub fn sign(
        &self,
        privkey_pem: &str,
        pubkey_pem: &str,
        alg: SigAlgKind,
    ) -> Result<SignedAnchor> {
        let actual_fp = KeyFp::from_pem(pubkey_pem)?;
        if actual_fp != self.signer.fp {
            return Err(Error::msg(format!(
                "signer fingerprint mismatch: anchor says {}, pubkey PEM is {}",
                self.signer.fp, actual_fp
            )));
        }
        if alg != self.signer.alg {
            return Err(Error::msg(format!(
                "signer algorithm mismatch: anchor says {}, caller passed {}",
                self.signer.alg, alg
            )));
        }
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
        let sig = pki::sign(alg, privkey_pem, &self.signing_bytes(), &mut rng)?;
        Ok(SignedAnchor {
            anchor: self.clone(),
            signature: sig,
        })
    }
}

/// Builder for [`Anchor`]. Enforces required fields; optional fields
/// chain-set. Final `.build()` returns the immutable `Anchor`.
pub struct AnchorBuilder {
    parents: Vec<AnchorHash>,
    signer: SignerId,
    timestamp: Option<String>,
    mutations: String,
    payload_hash: PayloadHash,
}

impl AnchorBuilder {
    pub fn with_parent(mut self, parent: AnchorHash) -> Self {
        self.parents.push(parent);
        self
    }

    pub fn with_parents(mut self, parents: Vec<AnchorHash>) -> Self {
        self.parents = parents;
        self
    }

    pub fn with_timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    pub fn with_mutations(mut self, m: impl Into<String>) -> Self {
        self.mutations = m.into();
        self
    }

    pub fn build(self) -> Anchor {
        Anchor {
            parents: self.parents,
            signer: self.signer,
            timestamp: self.timestamp,
            mutations: self.mutations,
            payload_hash: self.payload_hash,
        }
    }
}

/// An [`Anchor`] plus its detached signature. This is what gets
/// serialized into a `CHAIN` block in the file and what the DAG is
/// built out of.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAnchor {
    pub anchor: Anchor,
    pub signature: Vec<u8>,
}

impl SignedAnchor {
    /// Verify the signature against the embedded signer fingerprint
    /// using the supplied pubkey PEM. The PEM's fingerprint must
    /// match `anchor.signer.fp`.
    pub fn verify(&self, pubkey_pem: &str) -> Result<()> {
        let actual_fp = KeyFp::from_pem(pubkey_pem)?;
        if actual_fp != self.anchor.signer.fp {
            return Err(Error::msg(format!(
                "verifier fingerprint mismatch: anchor says {}, supplied pubkey is {}",
                self.anchor.signer.fp, actual_fp
            )));
        }
        let ok = pki::verify(
            self.anchor.signer.alg,
            pubkey_pem,
            &self.anchor.signing_bytes(),
            &self.signature,
        )?;
        if ok {
            Ok(())
        } else {
            Err(Error::msg("signature verification failed"))
        }
    }

    /// Convenience: the anchor's DAG identity.
    pub fn id(&self) -> Result<AnchorHash> {
        self.anchor.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_keypair() -> (String, String) {
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        pki::keygen(SigAlgKind::Ed25519, &mut rng).unwrap()
    }

    fn dummy_payload() -> PayloadHash {
        PayloadHash([0u8; 32])
    }

    #[test]
    fn signer_id_round_trips() {
        let fp = KeyFp::from_bytes([7u8; 32]);
        let id = SignerId::new(SigAlgKind::Ed25519, fp);
        let s = id.to_string();
        let parsed: SignerId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn signer_id_rejects_missing_colon() {
        assert!("no-colon-here".parse::<SignerId>().is_err());
    }

    #[test]
    fn signer_id_rejects_unknown_alg() {
        let result: Result<SignerId> =
            "rot13:0000000000000000000000000000000000000000000000000000000000000000".parse();
        assert!(result.is_err());
    }

    #[test]
    fn anchor_signing_bytes_are_stable() {
        let fp = KeyFp::from_bytes([1u8; 32]);
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);
        let anchor = Anchor::builder(signer, PayloadHash([2u8; 32]))
            .with_parent(AnchorHash([3u8; 32]))
            .with_timestamp("2026-07-25T00:00:00Z")
            .with_mutations("encrypt WORD=X")
            .build();

        let bytes1 = anchor.signing_bytes();
        let bytes2 = anchor.signing_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn anchor_id_is_deterministic() {
        let fp = KeyFp::from_bytes([1u8; 32]);
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);
        let anchor = Anchor::builder(signer, PayloadHash([2u8; 32]))
            .with_mutations("test")
            .build();
        let id1 = anchor.id().unwrap();
        let id2 = anchor.id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn anchor_id_changes_with_mutations() {
        let fp = KeyFp::from_bytes([1u8; 32]);
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);

        let a1 = Anchor::builder(signer.clone(), PayloadHash([2u8; 32]))
            .with_mutations("encrypt WORD=X")
            .build();
        let a2 = Anchor::builder(signer, PayloadHash([2u8; 32]))
            .with_mutations("encrypt WORD=Y") // different mutation
            .build();

        assert_ne!(a1.id().unwrap(), a2.id().unwrap());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);

        let anchor = Anchor::builder(signer, dummy_payload())
            .with_mutations("test mutation")
            .build();

        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();
        signed.verify(&pub_pem).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        let (_, other_pub) = ed25519_keypair();

        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);
        let anchor = Anchor::builder(signer, dummy_payload()).build();

        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();
        assert!(signed.verify(&other_pub).is_err());
    }

    #[test]
    fn sign_rejects_fingerprint_mismatch() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        // Synthetic fingerprint that doesn't correspond to any real key
        let unrelated_fp = KeyFp::from_bytes([0xff; 32]);

        let signer = SignerId::new(SigAlgKind::Ed25519, unrelated_fp);
        let anchor = Anchor::builder(signer, dummy_payload()).build();

        // anchor.signer.fp (synthetic) doesn't match pub_pem
        let result = anchor.sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);

        let anchor = Anchor::builder(signer.clone(), dummy_payload())
            .with_mutations("original")
            .build();
        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();

        // Tamper: same signing key but different payload hash
        let tampered = Anchor::builder(signer, PayloadHash([99u8; 32]))
            .with_mutations("original")
            .build();
        let tampered_signed = SignedAnchor {
            anchor: tampered,
            signature: signed.signature.clone(),
        };
        assert!(tampered_signed.verify(&pub_pem).is_err());
    }

    #[test]
    fn anchor_hash_hex_round_trips() {
        let h = AnchorHash([0xab; 32]);
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = AnchorHash::from_hex(&hex).unwrap();
        assert_eq!(h, parsed);
    }
}
