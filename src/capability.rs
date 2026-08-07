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

//! Capability model — the four-plus-one access tiers that every enprot
//! operation maps to.
//!
//! Every actor interacting with an EPT file holds some subset of
//! [`Capability`]. The tiers are mutually exclusive and collectively
//! exhaustive (MECE): each operation requires exactly one tier, and
//! every actor's reach can be described by the set of tiers they hold.
//!
//! | Tier        | Holds                  | Can do                                          |
//! |-------------|------------------------|-------------------------------------------------|
//! | `Viewer`    | nothing                | parse, list, verify structure, walk chain DAG   |
//! | `Reader`    | CAS path               | fetch `STORED` plaintext                         |
//! | `Decryptor` | WORD password          | decrypt that WORD's segments                     |
//! | `Signer`    | privkey                | produce chain anchors, detached signatures       |
//! | `Verifier`  | pubkey                 | verify signatures (no decryption)               |
//!
//! `Signer` and `Verifier` are dual halves of one capability; holding
//! the privkey implies signing capability, holding the pubkey implies
//! verifying capability. They are listed separately because the
//! operations are asymmetric.
//!
//! Capability sets union cleanly — this is the property that makes
//! merge-friendly operation possible (see TODO.finalize/19-merge-driver.md).

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use crate::crypto::{CryptoPolicyDefault, hexdigest};
use crate::error::{Error, Result};
use crate::etree::{ParseOps, TextNode};

/// A WORD identifier. Semantic alias around `String` so that capability
/// APIs can't accidentally accept arbitrary text.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct WordId(String);

impl WordId {
    pub fn new(s: impl Into<String>) -> Self {
        WordId(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA3-256 fingerprint of a pubkey PEM (the canonical form for
/// identifying keys in chain anchors and policy files). 32 bytes,
/// hex-displayed.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct KeyFp([u8; 32]);

impl KeyFp {
    /// Compute the fingerprint of a PEM-encoded pubkey.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let policy = CryptoPolicyDefault {};
        let hash = hexdigest("sha3-256", pem.as_bytes(), &policy)?;
        let mut arr = [0u8; 32];
        let bytes = hex::decode(&hash)?;
        if bytes.len() != 32 {
            return Err(Error::Hex(format!(
                "expected 32-byte SHA3-256, got {} bytes",
                bytes.len()
            )));
        }
        arr.copy_from_slice(&bytes);
        Ok(KeyFp(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct directly from raw bytes. Useful in tests and for
    /// deserializing wire formats (e.g., chain anchor `signer:` fields).
    pub fn from_bytes(arr: [u8; 32]) -> Self {
        KeyFp(arr)
    }

    /// Lowercase hex display, suitable for `signer:` fields in chain
    /// anchors and policy `trust_roots` lists.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for KeyFp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A single access tier. See the module docs for the full table.
///
/// `Viewer` is implied for any actor; `CapabilitySet::viewing()` is
/// the singleton baseline.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Capability {
    Viewer,
    Reader,
    Decryptor(WordId),
    Signer(KeyFp),
    Verifier(KeyFp),
}

// ---------------------------------------------------------------------
// SigningProvenance (TODO.completion/10)
//
// Records HOW a chain anchor's signature was produced. Verifier-
// agnostic on the wire (the signature bytes verify the same way
// regardless), but the capability ledger / inspect / audit log
// surfaces this metadata so auditors can answer "was this signed
// by a single key or by a 3-of-5 threshold session?"
// ---------------------------------------------------------------------

/// What kind of signer backend produced a signature.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum SignerBackend {
    /// Local PEM file (default `PemSigner`).
    Pem,
    /// OpenPGP via rnp-rs.
    OpenPGP,
    /// PKCS#11 hardware token.
    Pkcs11,
}

/// Threshold signing scheme. Mirrors Confium's `confium-tc-*` crate
/// taxonomy; extended as new threshold schemes ship.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ThresholdScheme {
    /// FROST over Ed25519 (`confium-tc-frost-ed25519`).
    FrostEd25519,
    /// FROST over ML-DSA-65 (`confium-tc-frost-ml-dsa-65`).
    FrostMlDsa65,
    /// FROST over P-256 (`confium-tc-frost-p256`).
    FrostP256,
    /// Threshold BLS for cross-org aggregation (`confium-tc-bls`).
    Bls,
    /// GG18 threshold ECDSA (`confium-tc-gg18`).
    Gg18,
    /// CMP20 threshold ECDSA over P-256 (`confium-tc-cmp20`).
    Cmp20,
}

/// Hardware key custody backend.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum HardwareBackend {
    Tpm,
    Hsm,
    Yubikey,
    CloudKMS,
}

/// Identifier for a threshold-signing party within a session.
/// Opaque string; specific format depends on the daemon (Confium
/// uses deployment-manifest actor IDs).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PartyId(pub String);

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a signature was produced. Carried by the capability ledger
/// alongside the anchor; NOT serialized into the chain anchor wire
/// format itself (which stays `signer:<alg>:<fp>` for verifier
/// portability — see TODO.completion/10).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigningProvenance {
    /// Single-party signature from local key material.
    /// `pubkey_fp` is the key's fingerprint; `backend` records how
    /// the key was loaded.
    Local {
        pubkey_fp: KeyFp,
        backend: SignerBackend,
    },
    /// Threshold signature from a Confium session (or compatible
    /// threshold backend). `group_fp` is the aggregate pubkey
    /// fingerprint; verifiers check this against their trust root.
    Threshold {
        scheme: ThresholdScheme,
        group_fp: KeyFp,
        threshold: u32,
        parties_total: u32,
        participants: Vec<PartyId>,
        session_id: String,
        daemon_endpoint: String,
        completed_at_unix: i64,
    },
    /// Hardware-backed single-party signature (TPM/HSM/YubiKey/cloud
    /// KMS via Confium store). Same wire bytes as Local but the
    /// ledger records that key material never left the device.
    HardwareBacked {
        pubkey_fp: KeyFp,
        backend: HardwareBackend,
        device_id: String,
    },
}

impl SigningProvenance {
    /// The fingerprint verifiers check against their trust root.
    /// For Local/HardwareBacked this is the key's own fp; for
    /// Threshold it's the aggregate group fp.
    pub fn signing_fingerprint(&self) -> &KeyFp {
        match self {
            SigningProvenance::Local { pubkey_fp, .. } => pubkey_fp,
            SigningProvenance::Threshold { group_fp, .. } => group_fp,
            SigningProvenance::HardwareBacked { pubkey_fp, .. } => pubkey_fp,
        }
    }

    /// True if this signature required multiple parties to coordinate.
    pub fn is_threshold(&self) -> bool {
        matches!(self, SigningProvenance::Threshold { .. })
    }

    /// True if the key material stayed in hardware (TPM/HSM/etc).
    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, SigningProvenance::HardwareBacked { .. })
    }
}

impl Capability {
    /// One-word tier name (`viewer`, `reader`, `decryptor`, `signer`,
    /// `verifier`) suitable for `list --capabilities` output.
    pub fn tier(&self) -> &'static str {
        match self {
            Capability::Viewer => "viewer",
            Capability::Reader => "reader",
            Capability::Decryptor(_) => "decryptor",
            Capability::Signer(_) => "signer",
            Capability::Verifier(_) => "verifier",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Viewer => f.write_str("viewer"),
            Capability::Reader => f.write_str("reader"),
            Capability::Decryptor(w) => write!(f, "decryptor({})", w),
            Capability::Signer(k) => write!(f, "signer({})", k),
            Capability::Verifier(k) => write!(f, "verifier({})", k),
        }
    }
}

/// A set of capabilities held by one actor. Set-union semantics:
/// merging two actors' views grows the union (the foundation of
/// merge-friendly distributed workflows).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet(HashSet<Capability>);

impl CapabilitySet {
    /// Empty set — call this `viewing()` to add the implicit Viewer.
    pub fn empty() -> Self {
        CapabilitySet(HashSet::new())
    }

    /// Baseline: anyone can view.
    pub fn viewing() -> Self {
        let mut s = Self::empty();
        s.0.insert(Capability::Viewer);
        s
    }

    /// Derive the capability set implied by a `ParseOps` configuration:
    /// always Viewer; Reader if the CAS dir exists and is readable;
    /// Decryptor(WORD) for each entry in `passwords`.
    ///
    /// Signer/Verifier are NOT derivable from `ParseOps` (which does
    /// not track key files). Use [`CapabilitySet::with_signer`] /
    /// [`CapabilitySet::with_verifier`] to add them.
    pub fn from_paops(paops: &ParseOps) -> Self {
        let mut s = Self::viewing();
        if Path::new(&paops.io.casdir).is_dir() {
            s.0.insert(Capability::Reader);
        }
        for word in paops.passwords.keys() {
            s.0.insert(Capability::Decryptor(WordId::new(word)));
        }
        s
    }

    /// Builder: add a Signer capability for a key fingerprint.
    pub fn with_signer(mut self, fp: KeyFp) -> Self {
        self.0.insert(Capability::Signer(fp));
        self
    }

    /// Builder: add a Verifier capability for a key fingerprint.
    pub fn with_verifier(mut self, fp: KeyFp) -> Self {
        self.0.insert(Capability::Verifier(fp));
        self
    }

    /// Insert a capability (mutable).
    pub fn insert(&mut self, c: Capability) {
        self.0.insert(c);
    }

    /// Set union — the operation that makes merges commute.
    pub fn union(mut self, other: &Self) -> Self {
        for c in &other.0 {
            self.0.insert(c.clone());
        }
        self
    }

    /// Membership check.
    pub fn contains(&self, c: &Capability) -> bool {
        self.0.contains(c)
    }

    /// Does this set satisfy the requirement set? A requirement set is
    /// just another `CapabilitySet`; satisfaction means every required
    /// capability is held. Decryptor is special: `Decryptor("Agent_007")`
    /// requirement is satisfied only by holding exactly that
    /// Decryptor — not by holding a different WORD's Decryptor.
    pub fn satisfies(&self, required: &Self) -> bool {
        for c in &required.0 {
            if !self.0.contains(c) {
                return false;
            }
        }
        true
    }

    /// Sorted iterator for stable display.
    pub fn iter_sorted(&self) -> Vec<&Capability> {
        let mut v: Vec<&Capability> = self.0.iter().collect();
        v.sort_by_key(|c| c.to_string());
        v
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sorted = self.iter_sorted();
        let parts: Vec<String> = sorted.iter().map(|c| c.to_string()).collect();
        f.write_str(&parts.join(", "))
    }
}

/// What capability tier is required to read/transform a given tree
/// node. Returns a `CapabilitySet` because some nodes might require
/// multiple capabilities in future (e.g., a signed encrypted block
/// would need Decryptor + Verifier).
///
/// Mapping (MECE):
/// - `Plain(_)` → Viewer
/// - `Data(_)` → Viewer (it's bytes; the surrounding Encrypted node dictates Decryptor)
/// - `Stored { .. }` → Reader (CAS access to fetch the blob)
/// - `BeginEnd { .. }` → Viewer
/// - `Encrypted { keyw, .. }` → Decryptor(keyw)
pub fn required_for(node: &TextNode) -> CapabilitySet {
    let mut s = CapabilitySet::viewing();
    match node {
        TextNode::Plain(_) => {}
        TextNode::Data(_) => {}
        TextNode::Stored { .. } => {
            s.insert(Capability::Reader);
        }
        TextNode::BeginEnd { .. } => {}
        TextNode::Encrypted { keyw, .. } => {
            s.insert(Capability::Decryptor(WordId::new(keyw)));
        }
        // Chain anchors require Verifier(pubkey-of-signer) to check
        // signatures, but we don't know the pubkey at this layer
        // (the `signer:` extfield would need parsing). Return Viewer
        // for now — verify-chain (TODO.finalize/18) does the proper
        // capability check with the resolved key.
        TextNode::Chain { .. } => {}
        // INCLUDE references require Reader (CAS access) to resolve.
        TextNode::Include { .. } => {
            s.insert(Capability::Reader);
        }
        // Conflict markers carry both sides verbatim. Required
        // capability is the union of what each side requires; caller
        // resolves and re-encrypts before they can act on it.
        TextNode::Conflict { ours, theirs, .. } => {
            for child in ours.iter().chain(theirs.iter()) {
                let child_req = required_for(child);
                for c in child_req.iter_sorted() {
                    s.insert(c.clone());
                }
            }
        }
        // RSD spec directives: IMMUTABLE/MUTED/KEY/CERT are atomic
        // metadata — no sub-nodes, no special capability requirement.
        TextNode::Immutable { .. }
        | TextNode::Muted { .. }
        | TextNode::Key { .. }
        | TextNode::Unkey { .. }
        | TextNode::Cert { .. }
        | TextNode::Uncert { .. } => {}
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etree::ParseOps;

    fn empty_paops() -> ParseOps {
        ParseOps::new(Box::new(crate::crypto::CryptoPolicyDefault {})).unwrap()
    }

    #[test]
    fn viewer_is_always_present() {
        let paops = empty_paops();
        let caps = CapabilitySet::from_paops(&paops);
        assert!(caps.contains(&Capability::Viewer));
    }

    #[test]
    fn reader_added_when_casdir_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let mut paops = empty_paops();
        paops.io.set_local_casdir(tmp.path().to_path_buf());
        let caps = CapabilitySet::from_paops(&paops);
        assert!(caps.contains(&Capability::Reader));
    }

    #[test]
    fn reader_not_added_when_casdir_missing() {
        let mut paops = empty_paops();
        paops
            .io
            .set_local_casdir("/nonexistent/path/that/does/not/exist".into());
        let caps = CapabilitySet::from_paops(&paops);
        assert!(!caps.contains(&Capability::Reader));
    }

    #[test]
    fn decryptor_added_per_password() {
        let mut paops = empty_paops();
        paops.passwords.insert("Agent_007".into(), "secret".into());
        paops.passwords.insert("GEHEIM".into(), "secret".into());
        let caps = CapabilitySet::from_paops(&paops);
        assert!(caps.contains(&Capability::Decryptor(WordId::new("Agent_007"))));
        assert!(caps.contains(&Capability::Decryptor(WordId::new("GEHEIM"))));
        assert!(!caps.contains(&Capability::Decryptor(WordId::new("OTHER"))));
    }

    #[test]
    fn decryptor_for_one_word_does_not_satisfy_another() {
        let mut paops = empty_paops();
        paops.passwords.insert("Agent_007".into(), "secret".into());
        let held = CapabilitySet::from_paops(&paops);

        let mut required = CapabilitySet::viewing();
        required.insert(Capability::Decryptor(WordId::new("Agent_007")));
        assert!(held.satisfies(&required));

        let mut required_other = CapabilitySet::viewing();
        required_other.insert(Capability::Decryptor(WordId::new("GEHEIM")));
        assert!(!held.satisfies(&required_other));
    }

    #[test]
    fn union_grows_capability_set() {
        let mut a = CapabilitySet::viewing();
        a.insert(Capability::Decryptor(WordId::new("Agent_007")));
        let mut b = CapabilitySet::viewing();
        b.insert(Capability::Decryptor(WordId::new("GEHEIM")));

        let u = a.union(&b);
        assert!(u.contains(&Capability::Decryptor(WordId::new("Agent_007"))));
        assert!(u.contains(&Capability::Decryptor(WordId::new("GEHEIM"))));
    }

    #[test]
    fn keyfp_from_pem_is_stable() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA9k0KvS0XUdLK8+nJSlQYlkqY8CyJa0nTK0YJGSk=\n-----END PUBLIC KEY-----\n";
        let fp1 = KeyFp::from_pem(pem).unwrap();
        let fp2 = KeyFp::from_pem(pem).unwrap();
        assert_eq!(fp1.to_hex(), fp2.to_hex());
        assert_eq!(fp1.to_hex().len(), 64); // 32 bytes hex
    }

    #[test]
    fn required_for_node_mappings_are_mece() {
        // Plain → Viewer only
        let plain_caps = required_for(&TextNode::Plain("hello".into()));
        assert_eq!(plain_caps.len(), 1);
        assert!(plain_caps.contains(&Capability::Viewer));

        // BeginEnd → Viewer only
        let be_caps = required_for(&TextNode::BeginEnd {
            keyw: "X".into(),
            txt: Vec::new(),
        });
        assert_eq!(be_caps.len(), 1);

        // Stored → Viewer + Reader
        let stored_caps = required_for(&TextNode::Stored {
            keyw: "ct".into(),
            cas: "abc".into(),
        });
        assert!(stored_caps.contains(&Capability::Viewer));
        assert!(stored_caps.contains(&Capability::Reader));

        // Encrypted → Viewer + Decryptor
        let enc_caps = required_for(&TextNode::Encrypted {
            keyw: "Agent_007".into(),
            txt: Vec::new(),
            extfields: std::collections::BTreeMap::new(),
        });
        assert!(enc_caps.contains(&Capability::Viewer));
        assert!(enc_caps.contains(&Capability::Decryptor(WordId::new("Agent_007"))));
    }

    #[test]
    fn display_is_stable_and_sorted() {
        let mut s = CapabilitySet::viewing();
        s.insert(Capability::Decryptor(WordId::new("Z")));
        s.insert(Capability::Decryptor(WordId::new("A")));
        let display = s.to_string();
        // Sorted alphabetically by Display form: "A" before "Z"
        let a_idx = display.find("A").unwrap();
        let z_idx = display.find("Z").unwrap();
        assert!(a_idx < z_idx);
    }
}
