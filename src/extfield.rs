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

//! Typed extfield accessors (TODO.finalize/46).
//!
//! The wire format stores extfields as a `BTreeMap<String, String>`
//! for forward-compatibility (unknown fields are preserved verbatim).
//! This module provides typed accessors so consumers don't have to
//! use string matching for known fields.
//!
//! The accessors are thin wrappers — they read from the BTreeMap
//! without copying. The map remains the source of truth; these
//! just provide type safety and documentation of which field
//! names exist.

use std::collections::BTreeMap;

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
}
