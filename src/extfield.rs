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

//! Typed extfield accessors + write-side enum (TODO.finalize/46 +
//! TODO.completion/16).
//!
//! The wire format stores extfields as a `BTreeMap<String, String>`
//! for forward-compatibility (unknown fields are preserved verbatim).
//! This module provides:
//!
//! - **Read side**: [`EncryptedExtFields`] / [`AnchorExtFields`]
//!   zero-cost borrowed views over the map.
//! - **Write side**: [`EncryptedExtField`] / [`AnchorExtField`] enums
//!   that own the wire representation. New callers build anchors with
//!   the typed enum and convert to a BTreeMap at the boundary; the
//!   compiler catches typos in field names that would otherwise be
//!   silent string bugs.

use std::collections::BTreeMap;

// ---------------------------------------------------------------------
// Read side: zero-cost borrowed views (unchanged from TODO.finalize/46)
// ---------------------------------------------------------------------

/// Typed view over Encrypted-block extfields. Zero-cost: borrows
/// the underlying map.
pub struct EncryptedExtFields<'a> {
    map: &'a BTreeMap<String, String>,
}

impl<'a> EncryptedExtFields<'a> {
    pub fn from_map(map: &'a BTreeMap<String, String>) -> Self {
        EncryptedExtFields { map }
    }

    /// The PHC-encoded PBKDF parameters. Absent for KEM-mode blocks.
    pub fn pbkdf(&self) -> Option<&str> {
        self.map.get("pbkdf").map(|s| s.as_str())
    }

    /// The cipher spec (e.g., `aes-256-gcm$iv=<base64>`). Absent
    /// for SIV-mode blocks (which don't carry an IV).
    pub fn cipher(&self) -> Option<&str> {
        self.map.get("cipher").map(|s| s.as_str())
    }

    /// True if this block uses KEM-mode encryption (has a
    /// `recipients:` field).
    pub fn is_kem_mode(&self) -> bool {
        self.map.contains_key("recipients")
    }

    /// Comma-separated recipient fingerprints (`mlkem:<fp>,...`).
    pub fn recipients(&self) -> Option<&str> {
        self.map.get("recipients").map(|s| s.as_str())
    }

    /// Look up a specific recipient's KEM ciphertext by fingerprint.
    pub fn recipient_ct(&self, fp_hex: &str) -> Option<&str> {
        self.map
            .get(&format!("recipient-mlkem-{}", fp_hex))
            .map(|s| s.as_str())
    }

    /// The compression algorithm (currently always `zlib`). Absent
    /// means the plaintext was not compressed before encryption.
    pub fn compress(&self) -> Option<&str> {
        self.map.get("compress").map(|s| s.as_str())
    }

    /// Raw access to the underlying map for fields not covered by
    /// typed accessors (e.g., future fields).
    pub fn raw(&self) -> &BTreeMap<String, String> {
        self.map
    }
}

/// Typed view over CHAIN-block (anchor) extfields.
pub struct AnchorExtFields<'a> {
    map: &'a BTreeMap<String, String>,
}

impl<'a> AnchorExtFields<'a> {
    pub fn from_map(map: &'a BTreeMap<String, String>) -> Self {
        AnchorExtFields { map }
    }

    pub fn signer(&self) -> Option<&str> {
        self.map.get("signer").map(|s| s.as_str())
    }

    pub fn signers(&self) -> Option<&str> {
        self.map.get("signers").map(|s| s.as_str())
    }

    pub fn payload(&self) -> Option<&str> {
        self.map.get("payload").map(|s| s.as_str())
    }

    pub fn sig(&self) -> Option<&str> {
        self.map.get("sig").map(|s| s.as_str())
    }

    pub fn sigs(&self) -> Option<&str> {
        self.map.get("sigs").map(|s| s.as_str())
    }

    pub fn parents(&self) -> Option<&str> {
        self.map.get("parents").map(|s| s.as_str())
    }

    pub fn timestamp(&self) -> Option<&str> {
        self.map.get("ts").map(|s| s.as_str())
    }

    pub fn mutations(&self) -> Option<&str> {
        self.map.get("mut").map(|s| s.as_str())
    }

    pub fn is_multi_sig(&self) -> bool {
        self.map.contains_key("signers")
    }

    pub fn raw(&self) -> &BTreeMap<String, String> {
        self.map
    }
}

// ---------------------------------------------------------------------
// Write side: typed enums (TODO.completion/16)
//
// Owns the wire representation; converts to/from BTreeMap at the
// boundary. Field names are now compile-time checked.
// ---------------------------------------------------------------------

/// Typed encrypted-block extfield. Convert to wire via `into_entry()`;
/// parse from wire via `from_entry()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptedExtField {
    /// PHC-encoded PBKDF parameters (e.g. `$argon2id$m=65536,t=3,p=4$…`).
    Pbkdf(String),
    /// Cipher spec (e.g. `aes-256-gcm$iv=…`).
    Cipher(String),
    /// Compression algorithm (currently always `zlib`).
    Compress(String),
    /// Comma-separated recipient fingerprints for KEM-mode blocks.
    Recipients(String),
    /// Per-recipient KEM ciphertext, keyed by fingerprint.
    RecipientMlKemCt { fp_hex: String, ct_base64: String },
    /// Attribute-based access predicate (URL-encoded; TODO.completion/11).
    Attribute(String),
    /// Unknown field preserved verbatim for forward compatibility.
    Unknown { key: String, value: String },
}

impl EncryptedExtField {
    /// Convert to the wire-format (key, value) pair for insertion
    /// into the BTreeMap<String, String>.
    pub fn into_entry(self) -> (String, String) {
        match self {
            EncryptedExtField::Pbkdf(v) => ("pbkdf".to_string(), v),
            EncryptedExtField::Cipher(v) => ("cipher".to_string(), v),
            EncryptedExtField::Compress(v) => ("compress".to_string(), v),
            EncryptedExtField::Recipients(v) => ("recipients".to_string(), v),
            EncryptedExtField::RecipientMlKemCt { fp_hex, ct_base64 } => {
                (format!("recipient-mlkem-{}", fp_hex), ct_base64)
            }
            EncryptedExtField::Attribute(v) => ("attr".to_string(), v),
            EncryptedExtField::Unknown { key, value } => (key, value),
        }
    }

    /// Convenience: convert to (key, value) and insert into a map.
    /// Eliminates raw string keys at call sites — the field name is
    /// compile-time checked via the enum variant.
    pub fn insert_into(self, map: &mut BTreeMap<String, String>) {
        let (k, v) = self.into_entry();
        map.insert(k, v);
    }

    /// Parse a wire-format (key, value) pair into the typed enum.
    /// Known keys produce their variant; unknown keys produce
    /// [`EncryptedExtField::Unknown`] so they survive round-trips.
    pub fn from_entry(key: &str, value: &str) -> Self {
        match key {
            "pbkdf" => EncryptedExtField::Pbkdf(value.to_string()),
            "cipher" => EncryptedExtField::Cipher(value.to_string()),
            "compress" => EncryptedExtField::Compress(value.to_string()),
            "recipients" => EncryptedExtField::Recipients(value.to_string()),
            "attr" => EncryptedExtField::Attribute(value.to_string()),
            other if other.starts_with("recipient-mlkem-") => EncryptedExtField::RecipientMlKemCt {
                fp_hex: other["recipient-mlkem-".len()..].to_string(),
                ct_base64: value.to_string(),
            },
            _ => EncryptedExtField::Unknown {
                key: key.to_string(),
                value: value.to_string(),
            },
        }
    }
}

/// Typed anchor-block extfield. Same shape as [`EncryptedExtField`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorExtField {
    /// `<alg>:<fp>` for single-signer anchors.
    Signer(String),
    /// Comma-separated `<alg>:<fp>,…` for multi-signer anchors.
    Signers(String),
    /// SHA3-256 hex of the file-tree state at this anchor.
    Payload(String),
    /// Hex-encoded signature (single-signer).
    Sig(String),
    /// Comma-separated hex signatures (multi-signer).
    Sigs(String),
    /// Comma-separated parent anchor hashes.
    Parents(String),
    /// Compact RFC 3339 timestamp.
    Timestamp(String),
    /// Human-readable mutation description.
    Mutation(String),
    /// Unknown field preserved verbatim.
    Unknown { key: String, value: String },
}

impl AnchorExtField {
    pub fn into_entry(self) -> (String, String) {
        match self {
            AnchorExtField::Signer(v) => ("signer".to_string(), v),
            AnchorExtField::Signers(v) => ("signers".to_string(), v),
            AnchorExtField::Payload(v) => ("payload".to_string(), v),
            AnchorExtField::Sig(v) => ("sig".to_string(), v),
            AnchorExtField::Sigs(v) => ("sigs".to_string(), v),
            AnchorExtField::Parents(v) => ("parents".to_string(), v),
            AnchorExtField::Timestamp(v) => ("ts".to_string(), v),
            AnchorExtField::Mutation(v) => ("mut".to_string(), v),
            AnchorExtField::Unknown { key, value } => (key, value),
        }
    }

    pub fn from_entry(key: &str, value: &str) -> Self {
        match key {
            "signer" => AnchorExtField::Signer(value.to_string()),
            "signers" => AnchorExtField::Signers(value.to_string()),
            "payload" => AnchorExtField::Payload(value.to_string()),
            "sig" => AnchorExtField::Sig(value.to_string()),
            "sigs" => AnchorExtField::Sigs(value.to_string()),
            "parents" => AnchorExtField::Parents(value.to_string()),
            "ts" => AnchorExtField::Timestamp(value.to_string()),
            "mut" => AnchorExtField::Mutation(value.to_string()),
            _ => AnchorExtField::Unknown {
                key: key.to_string(),
                value: value.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn encrypted_extfields_reads_known_fields() {
        let m = map(&[
            ("pbkdf", "$argon2$m=65536,t=3,p=4$salt$"),
            ("cipher", "aes-256-gcm$iv=MDEyMzQ1Njc4OWFiY2RlZg=="),
        ]);
        let ef = EncryptedExtFields::from_map(&m);
        assert!(ef.pbkdf().is_some());
        assert!(ef.cipher().is_some());
        assert!(!ef.is_kem_mode());
        assert!(ef.recipients().is_none());
    }

    #[test]
    fn encrypted_extfields_detects_kem_mode() {
        let m = map(&[
            ("recipients", "mlkem:1c8d2e...,mlkem:9f3a7b..."),
            ("recipient-mlkem-1c8d2e...", "YmFzZTY0Cg=="),
        ]);
        let ef = EncryptedExtFields::from_map(&m);
        assert!(ef.is_kem_mode());
        assert!(ef.pbkdf().is_none());
        assert!(ef.recipients().is_some());
        assert!(ef.recipient_ct("1c8d2e...").is_some());
        assert!(ef.recipient_ct("9f3a7b...").is_none()); // only has the first
    }

    #[test]
    fn anchor_extfields_reads_single_and_multi_sig() {
        let single = map(&[("signer", "ed25519:abc..."), ("sig", "deadbeef...")]);
        let multi = map(&[
            ("signer", "ed25519:abc..."),
            ("sig", "deadbeef..."),
            ("signers", "ed25519:abc...,ed25519:def..."),
            ("sigs", "deadbeef...,cafebabe..."),
        ]);
        let sef = AnchorExtFields::from_map(&single);
        assert!(!sef.is_multi_sig());
        assert!(sef.signer().is_some());

        let mef = AnchorExtFields::from_map(&multi);
        assert!(mef.is_multi_sig());
        assert!(mef.signers().is_some());
        assert!(mef.sigs().is_some());
    }

    // --- Write-side enum tests (TODO.completion/16) ---

    #[test]
    fn encrypted_extfield_round_trips_through_entry() {
        for original in [
            EncryptedExtField::Pbkdf("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash".to_string()),
            EncryptedExtField::Cipher("aes-256-gcm$iv=MDEy".to_string()),
            EncryptedExtField::Compress("zlib".to_string()),
            EncryptedExtField::Recipients("mlkem:abc...,mlkem:def...".to_string()),
            EncryptedExtField::RecipientMlKemCt {
                fp_hex: "abc...".to_string(),
                ct_base64: "YmFzZTY0Cg==".to_string(),
            },
            EncryptedExtField::Attribute("clearance%3E%3DSECRET".to_string()),
            EncryptedExtField::Unknown {
                key: "x-future-field".to_string(),
                value: "preserved".to_string(),
            },
        ] {
            let (k, v) = original.clone().into_entry();
            let recovered = EncryptedExtField::from_entry(&k, &v);
            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn anchor_extfield_round_trips_through_entry() {
        for original in [
            AnchorExtField::Signer("ed25519:9f3a7b...".to_string()),
            AnchorExtField::Signers("ed25519:abc...,ed25519:def...".to_string()),
            AnchorExtField::Payload("a3f5...".to_string()),
            AnchorExtField::Sig("deadbeef...".to_string()),
            AnchorExtField::Sigs("deadbeef...,cafebabe...".to_string()),
            AnchorExtField::Parents("a3f5...,b2c4...".to_string()),
            AnchorExtField::Timestamp("20260728T143000Z".to_string()),
            AnchorExtField::Mutation("encrypted+signed".to_string()),
            AnchorExtField::Unknown {
                key: "x-future".to_string(),
                value: "v".to_string(),
            },
        ] {
            let (k, v) = original.clone().into_entry();
            let recovered = AnchorExtField::from_entry(&k, &v);
            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn typed_extfield_collects_into_btreemap() {
        let fields = vec![
            AnchorExtField::Signer("ed25519:abc".to_string()),
            AnchorExtField::Sig("deadbeef".to_string()),
            AnchorExtField::Payload("a3f5".to_string()),
        ];
        let wire: BTreeMap<String, String> =
            fields.into_iter().map(AnchorExtField::into_entry).collect();
        assert_eq!(wire.get("signer").map(|s| s.as_str()), Some("ed25519:abc"));
        assert_eq!(wire.get("sig").map(|s| s.as_str()), Some("deadbeef"));
        assert_eq!(wire.get("payload").map(|s| s.as_str()), Some("a3f5"));
    }
}
