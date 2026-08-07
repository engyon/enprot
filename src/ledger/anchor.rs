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
            return Err(Error::Hex(format!(
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
        let (alg_str, fp_str) = s.split_once(':').ok_or_else(|| Error::Extfield {
            field: "signer",
            reason: format!("malformed signer id '{s}', expected '<alg>:<fp>'"),
        })?;
        let alg: SigAlgKind = alg_str.parse()?;
        let fp_bytes = hex::decode(fp_str)?;
        if fp_bytes.len() != 32 {
            return Err(Error::Hex(format!(
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
/// commits to `parents || signer || co_signers || timestamp || payload-hash`
/// (the mutations field is informational, not signed, so it can be edited
/// later for translation/clarity without invalidating the signature).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    /// SHA3-256 hashes of preceding anchors this one builds on.
    /// Genesis anchor has zero parents. Merge anchor has 2+.
    pub parents: Vec<AnchorHash>,

    /// Who signed this anchor and with what algorithm. For multi-sig
    /// anchors (TODO.roadmap/57), this is the *primary* signer; the
    /// full signer set is `[signer].iter().chain(co_signers.iter())`.
    pub signer: SignerId,

    /// Additional signers for multi-sig anchors (TODO.roadmap/57).
    /// Empty for single-signer anchors (the common case). Each entry
    /// must sign the same `signing_bytes` as the primary signer; the
    /// wire format records one `sig` per signer in the same order.
    pub co_signers: Vec<SignerId>,

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
        // co_signers are part of the signed payload so a malicious
        // signer can't silently strip a co-signer's entry from the
        // wire format. Each co_signer is appended in order.
        for cs in &self.co_signers {
            out.extend_from_slice(cs.to_string().as_bytes());
        }
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
            return Err(Error::SignatureVerify {
                key_id: format!(
                    "fingerprint mismatch: anchor={}, pubkey={}",
                    self.signer.fp, actual_fp
                ),
            });
        }
        if alg != self.signer.alg {
            return Err(Error::SignatureVerify {
                key_id: format!(
                    "algorithm mismatch: anchor={}, caller={}",
                    self.signer.alg, alg
                ),
            });
        }
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(Error::botan)?;
        let sig = pki::sign(alg, privkey_pem, &self.signing_bytes(), &mut rng)?;
        Ok(SignedAnchor {
            anchor: self.clone(),
            signature: sig,
            co_signatures: Vec::new(),
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
            co_signers: Vec::new(),
            timestamp: self.timestamp,
            mutations: self.mutations,
            payload_hash: self.payload_hash,
        }
    }
}

/// An [`Anchor`] plus its detached signature. This is what gets
/// serialized into a `CHAIN` block in the file and what the DAG is
/// built out of.
///
/// For multi-sig anchors (TODO.roadmap/57), `co_signatures` carries
/// the additional signatures in the same order as `anchor.co_signers`.
/// Single-signer anchors leave `co_signatures` empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAnchor {
    pub anchor: Anchor,
    pub signature: Vec<u8>,
    pub co_signatures: Vec<Vec<u8>>,
}

impl SignedAnchor {
    /// Verify the primary signature against the embedded signer
    /// fingerprint using the supplied pubkey PEM. For multi-sig
    /// anchors (TODO.roadmap/57), use [`Self::verify_multi`] which
    /// checks every signature.
    pub fn verify(&self, pubkey_pem: &str) -> Result<()> {
        let actual_fp = KeyFp::from_pem(pubkey_pem)?;
        if actual_fp != self.anchor.signer.fp {
            return Err(Error::SignatureVerify {
                key_id: format!(
                    "fingerprint mismatch: anchor={}, pubkey={}",
                    self.anchor.signer.fp, actual_fp
                ),
            });
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
            Err(Error::SignatureVerify {
                key_id: self.anchor.signer.to_string(),
            })
        }
    }

    /// Verify every signature on a multi-sig anchor. `resolver`
    /// maps each signer fingerprint hex to the corresponding pubkey
    /// PEM. Every signature must validate; a single bad signature
    /// fails the whole anchor. (TODO.roadmap/57.)
    pub fn verify_multi<F>(&self, resolver: F) -> Result<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        // Verify primary first.
        let primary_fp_hex = self.anchor.signer.fp.to_hex();
        let primary_pem = resolver(&primary_fp_hex).ok_or_else(|| Error::SignatureVerify {
            key_id: format!("no pubkey registered for primary signer {primary_fp_hex}"),
        })?;
        self.verify(&primary_pem)?;
        // Then each co-signer in order.
        for (cs, cosig) in self.anchor.co_signers.iter().zip(self.co_signatures.iter()) {
            let fp_hex = cs.fp.to_hex();
            let pem = resolver(&fp_hex).ok_or_else(|| Error::SignatureVerify {
                key_id: format!("no pubkey registered for co-signer {fp_hex}"),
            })?;
            let ok = pki::verify(cs.alg, &pem, &self.anchor.signing_bytes(), cosig)?;
            if !ok {
                return Err(Error::SignatureVerify {
                    key_id: format!("co-signer {fp_hex} signature verification failed"),
                });
            }
        }
        Ok(())
    }

    /// Append a co-signer's signature. The signature must be over
    /// `self.anchor.signing_bytes()` — which already includes the
    /// co_signers list, so all co-signers must be registered before
    /// any signature is produced. (TODO.roadmap/57.)
    pub fn add_co_signature(&mut self, co_signer: SignerId, signature: Vec<u8>) -> Result<()> {
        // The signing_bytes must already reflect this co_signer;
        // otherwise the primary signer signed different bytes than
        // the co-signer did, and verification will fail.
        if !self.anchor.co_signers.contains(&co_signer) {
            return Err(Error::SignatureVerify {
                key_id: format!(
                    "co-signer {co_signer} not in anchor.co_signers; append it before any signature is produced"
                ),
            });
        }
        self.co_signatures.push(signature);
        Ok(())
    }

    /// Convenience: the anchor's DAG identity.
    pub fn id(&self) -> Result<AnchorHash> {
        self.anchor.id()
    }

    /// Serialize to the wire-format `key:value` extfield map used by
    /// the `CHAIN` directive (TODO.finalize/17). Round-trips through
    /// [`SignedAnchor::from_extfields`].
    ///
    /// Single-signer fields: `parents` (comma-separated hex),
    /// `signer` (`<alg>:<fp-hex>`), `ts` (RFC 3339, optional),
    /// `mut` (description, optional), `payload` (hex), `sig` (hex).
    ///
    /// Multi-signer fields (TODO.roadmap/57, emitted when
    /// `co_signatures` is non-empty): `signers` (comma-separated
    /// `<alg>:<fp-hex>`), `sigs` (comma-separated hex). The
    /// single-signer `signer` and `sig` fields are still emitted
    /// with the primary signer's values so older verifiers that
    /// don't know about `signers` see a consistent (single-sig)
    /// view of the anchor — they'll verify only the primary
    /// signature and miss the co-signatures, but won't reject.
    pub fn to_extfields(&self) -> std::collections::BTreeMap<String, String> {
        let mut m = std::collections::BTreeMap::new();
        if !self.anchor.parents.is_empty() {
            let joined = self
                .anchor
                .parents
                .iter()
                .map(|h| h.to_hex())
                .collect::<Vec<_>>()
                .join(",");
            m.insert("parents".into(), joined);
        }
        m.insert("signer".into(), self.anchor.signer.to_string());
        if let Some(ref ts) = self.anchor.timestamp {
            m.insert("ts".into(), ts.clone());
        }
        if !self.anchor.mutations.is_empty() {
            m.insert("mut".into(), self.anchor.mutations.clone());
        }
        m.insert("payload".into(), self.anchor.payload_hash.to_hex());
        m.insert("sig".into(), hex::encode(&self.signature));
        if !self.co_signatures.is_empty() {
            let signers = std::iter::once(&self.anchor.signer)
                .chain(self.anchor.co_signers.iter())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");
            m.insert("signers".into(), signers);
            let sigs = std::iter::once(&self.signature)
                .chain(self.co_signatures.iter())
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(",");
            m.insert("sigs".into(), sigs);
        }
        m
    }

    /// Parse a wire-format extfield map (as produced by the CHAIN
    /// directive parser) into a [`SignedAnchor`]. Inverse of
    /// [`SignedAnchor::to_extfields`].
    ///
    /// Single-sig required fields: `signer`, `payload`, `sig`.
    /// Multi-sig (TODO.roadmap/57): if `signers` is present, the
    /// list is parsed in order; the first entry populates the
    /// single-signer fields, the rest populate `co_signers` and
    /// `co_signatures`. Optional: `ts`, `mut`, `parents`.
    pub fn from_extfields(extfields: &std::collections::BTreeMap<String, String>) -> Result<Self> {
        let payload_str = extfields.get("payload").ok_or_else(|| Error::Extfield {
            field: "payload",
            reason: "CHAIN missing required 'payload' field".to_string(),
        })?;
        let payload_hash = PayloadHash::from_hex(payload_str)?;

        let parents: Vec<AnchorHash> = extfields
            .get("parents")
            .map(|s| {
                s.split(',')
                    .filter(|p| !p.is_empty())
                    .map(AnchorHash::from_hex)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        let timestamp = extfields.get("ts").cloned();
        let mutations = extfields.get("mut").cloned().unwrap_or_default();

        // Multi-sig mode takes precedence when the `signers` field
        // is present. The single-sig `signer` and `sig` fields are
        // still required (they hold the primary signer's data) so
        // older producers and consumers stay consistent.
        let (signer, co_signers, signature, co_signatures) =
            if let Some(signers_str) = extfields.get("signers") {
                let sigs_str = extfields.get("sigs").ok_or_else(|| Error::Extfield {
                    field: "sigs",
                    reason: "multi-sig CHAIN missing 'sigs' field".to_string(),
                })?;
                let signer_ids: Vec<SignerId> = signers_str
                    .split(',')
                    .map(|s| s.parse::<SignerId>())
                    .collect::<Result<Vec<_>>>()?;
                let sigs: Vec<Vec<u8>> = sigs_str
                    .split(',')
                    .map(|s| hex::decode(s).map_err(Error::from))
                    .collect::<Result<Vec<_>>>()?;
                if signer_ids.len() != sigs.len() {
                    return Err(Error::Extfield {
                        field: "signers",
                        reason: format!(
                            "multi-sig CHAIN: {} signers vs {} sigs (must match)",
                            signer_ids.len(),
                            sigs.len()
                        ),
                    });
                }
                if signer_ids.is_empty() {
                    return Err(Error::Extfield {
                        field: "signers",
                        reason: "multi-sig CHAIN: empty signers list".to_string(),
                    });
                }
                let primary_signer = signer_ids[0].clone();
                let primary_sig = sigs[0].clone();
                let co_signers = signer_ids[1..].to_vec();
                let co_signatures = sigs[1..].to_vec();
                (primary_signer, co_signers, primary_sig, co_signatures)
            } else {
                let signer_str = extfields.get("signer").ok_or_else(|| Error::Extfield {
                    field: "signer",
                    reason: "CHAIN missing required 'signer' field".to_string(),
                })?;
                let signer: SignerId = signer_str.parse()?;
                let sig_str = extfields.get("sig").ok_or_else(|| Error::Extfield {
                    field: "sig",
                    reason: "CHAIN missing required 'sig' field".to_string(),
                })?;
                let signature = hex::decode(sig_str)?;
                (signer, Vec::new(), signature, Vec::new())
            };

        let anchor = Anchor {
            parents,
            signer,
            co_signers,
            timestamp,
            mutations,
            payload_hash,
        };

        Ok(SignedAnchor {
            anchor,
            signature,
            co_signatures,
        })
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
    fn multi_sig_anchor_round_trips() {
        // TODO.roadmap/57: an anchor with N signers round-trips
        // through to_extfields / from_extfields and verifies under
        // verify_multi with all signers' pubkeys.
        let (priv1, pub1) = ed25519_keypair();
        let (priv2, pub2) = ed25519_keypair();
        let fp1 = KeyFp::from_pem(&pub1).unwrap();
        let fp2 = KeyFp::from_pem(&pub2).unwrap();
        let signer1 = SignerId::new(SigAlgKind::Ed25519, fp1);
        let signer2 = SignerId::new(SigAlgKind::Ed25519, fp2);

        // Build the anchor with both co_signers BEFORE signing so
        // signing_bytes reflects the full signer set.
        let mut anchor = Anchor::builder(signer1, dummy_payload())
            .with_mutations("multi-sig test")
            .build();
        anchor.co_signers.push(signer2.clone());

        // Primary signs first.
        let mut signed = anchor.sign(&priv1, &pub1, SigAlgKind::Ed25519).unwrap();
        // Co-signer signs the same bytes.
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let cosig = pki::sign(
            SigAlgKind::Ed25519,
            &priv2,
            &anchor.signing_bytes(),
            &mut rng,
        )
        .unwrap();
        signed.add_co_signature(signer2, cosig).unwrap();

        // Wire format round-trip.
        let ext = signed.to_extfields();
        let rebuilt = SignedAnchor::from_extfields(&ext).unwrap();
        assert_eq!(rebuilt, signed);

        // Multi-sig verify with a resolver that knows both pubkeys.
        let resolver = |fp_hex: &str| {
            if fp_hex == fp1.to_hex() {
                Some(pub1.clone())
            } else if fp_hex == fp2.to_hex() {
                Some(pub2.clone())
            } else {
                None
            }
        };
        signed.verify_multi(resolver).unwrap();
    }

    #[test]
    fn multi_sig_verify_rejects_missing_co_signer_pubkey() {
        let (priv1, pub1) = ed25519_keypair();
        let (priv2, _pub2) = ed25519_keypair();
        let fp1 = KeyFp::from_pem(&pub1).unwrap();
        let fp2 = KeyFp::from_pem(&_pub2).unwrap();
        let signer1 = SignerId::new(SigAlgKind::Ed25519, fp1);
        let signer2 = SignerId::new(SigAlgKind::Ed25519, fp2);

        let mut anchor = Anchor::builder(signer1, dummy_payload()).build();
        anchor.co_signers.push(signer2.clone());
        let mut signed = anchor.sign(&priv1, &pub1, SigAlgKind::Ed25519).unwrap();
        let mut rng = botan::RandomNumberGenerator::new_system().unwrap();
        let cosig = pki::sign(
            SigAlgKind::Ed25519,
            &priv2,
            &anchor.signing_bytes(),
            &mut rng,
        )
        .unwrap();
        signed.add_co_signature(signer2, cosig).unwrap();

        // Resolver only knows the primary; co-signer lookup fails.
        let resolver = |fp_hex: &str| {
            if fp_hex == fp1.to_hex() {
                Some(pub1.clone())
            } else {
                None
            }
        };
        assert!(signed.verify_multi(resolver).is_err());
    }

    #[test]
    fn multi_sig_single_signer_backwards_compat() {
        // An anchor with no co_signers produces wire format
        // indistinguishable from the legacy single-sig format:
        // no `signers` or `sigs` field is emitted.
        let (priv_pem, pub_pem) = ed25519_keypair();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);
        let anchor = Anchor::builder(signer, dummy_payload()).build();
        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();
        let ext = signed.to_extfields();
        assert!(!ext.contains_key("signers"));
        assert!(!ext.contains_key("sigs"));
        assert!(ext.contains_key("signer"));
        assert!(ext.contains_key("sig"));
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
            co_signatures: Vec::new(),
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

    #[test]
    fn signed_anchor_extfields_round_trip() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);

        let parent = AnchorHash([0xaa; 32]);
        let anchor = Anchor::builder(signer, PayloadHash([0xbb; 32]))
            .with_parent(parent)
            .with_timestamp("20260725T143000Z")
            .with_mutations("encrypt+WORD")
            .build();
        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();

        let ext = signed.to_extfields();
        let rebuilt = SignedAnchor::from_extfields(&ext).unwrap();
        assert_eq!(rebuilt.anchor, signed.anchor);
        assert_eq!(rebuilt.signature, signed.signature);
    }

    #[test]
    fn from_extfields_rejects_missing_required() {
        let mut m = std::collections::BTreeMap::new();
        // Missing everything → error
        assert!(SignedAnchor::from_extfields(&m).is_err());

        // Missing sig only
        m.insert(
            "signer".into(),
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        m.insert(
            "payload".into(),
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
        );
        assert!(SignedAnchor::from_extfields(&m).is_err());
    }

    #[test]
    fn from_extfields_rejects_malformed_hex() {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "signer".into(),
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        m.insert("payload".into(), "not-hex!".into());
        m.insert("sig".into(), "ab".into());
        assert!(SignedAnchor::from_extfields(&m).is_err());
    }

    #[test]
    fn genesis_anchor_round_trips_without_parents() {
        let (priv_pem, pub_pem) = ed25519_keypair();
        let fp = KeyFp::from_pem(&pub_pem).unwrap();
        let signer = SignerId::new(SigAlgKind::Ed25519, fp);
        let anchor = Anchor::builder(signer, PayloadHash([0x11; 32])).build();
        let signed = anchor
            .sign(&priv_pem, &pub_pem, SigAlgKind::Ed25519)
            .unwrap();

        let ext = signed.to_extfields();
        // Genesis anchor: no parents field
        assert!(!ext.contains_key("parents"));
        let rebuilt = SignedAnchor::from_extfields(&ext).unwrap();
        assert!(rebuilt.anchor.parents.is_empty());
    }
}
