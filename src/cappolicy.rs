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

//! Capability policy enforcement (TODO.roadmap/46).
//!
//! A `CapPolicy` is a TOML document that pins trust roots, requires
//! monotonic timestamps, and declares per-WORD required capabilities
//! and recipient whitelists. The CLI loads it via `--policy-file` and
//! consults it from two places:
//!
//! - `verify-chain`: checks trust_roots and timestamp monotonicity.
//! - `encrypt`: refuses to write blocks for a WORD whose required
//!   capability the caller doesn't hold.
//!
//! Recipient whitelisting (per-WORD `accepted_recipients`) is parsed
//! and surfaced through introspection, but not yet enforced: it
//! requires ML-KEM-based encryption to be wired through the encrypt
//! pipeline (TODO.roadmap/30).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::capability::{Capability, CapabilitySet, KeyFp};
use crate::error::{Error, Result};
use crate::ledger::anchor::SignerId;

/// Parsed `.enprot/policy.toml`.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapPolicy {
    #[serde(default)]
    pub chain: ChainPolicy,
    /// Per-WORD requirements. Renamed to `word` on the wire so the
    /// TOML reads `[[word]]` (singular section name, idiomatic for
    /// TOML arrays-of-tables).
    #[serde(default, rename = "word")]
    pub words: Vec<WordPolicy>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainPolicy {
    /// `<alg>:<fp-hex>` strings. When non-empty, `verify-chain` rejects
    /// any anchor whose signer isn't in this list.
    #[serde(default)]
    pub trust_roots: Vec<String>,
    /// When true, anchor timestamps must be strictly increasing along
    /// the DAG's parent edges.
    #[serde(default)]
    pub require_monotonic_timestamps: bool,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct WordPolicy {
    pub name: String,
    /// `viewer`, `reader`, `decryptor`, `signer`, `verifier`.
    pub required_capability: String,
    /// `<alg>:<fp-hex>` recipient keys permitted for this WORD.
    /// Enforcement is gated on ML-KEM landing in the encrypt pipeline.
    #[serde(default)]
    pub accepted_recipients: Vec<String>,
}

impl CapPolicy {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| Error::Json(format!("policy parse: {e}")))
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_toml_str(&s)
    }

    /// True if `signer` is in `chain.trust_roots` (or if the policy
    /// leaves trust_roots empty — empty means "no whitelist").
    pub fn trust_root_allows(&self, signer: &SignerId) -> bool {
        if self.chain.trust_roots.is_empty() {
            return true;
        }
        let formatted = signer.to_string();
        self.chain
            .trust_roots
            .iter()
            .any(|root| root.eq_ignore_ascii_case(&formatted))
    }

    /// Verify the caller holds the required capability for `word`.
    /// Returns `Ok(())` if no policy entry exists for the WORD.
    pub fn check_word_capability(&self, word: &str, held: &CapabilitySet) -> Result<()> {
        let Some(policy) = self.words.iter().find(|w| w.name == word) else {
            return Ok(());
        };
        let required = parse_capability(&policy.required_capability).ok_or_else(|| {
            Error::PolicyViolation {
                rule: "word.required_capability".into(),
                context: format!(
                    "unknown capability '{}' for WORD {}",
                    policy.required_capability, policy.name
                ),
            }
        })?;
        if held.contains(&required) {
            Ok(())
        } else {
            Err(Error::PolicyViolation {
                rule: "word.required_capability".into(),
                context: format!(
                    "WORD {} requires {}; caller does not hold it",
                    word, policy.required_capability
                ),
            })
        }
    }
}

fn parse_capability(s: &str) -> Option<Capability> {
    match s.to_ascii_lowercase().as_str() {
        "viewer" => Some(Capability::Viewer),
        "reader" => Some(Capability::Reader),
        // Decryptor requires a WORD; the policy's required_capability
        // field doesn't carry per-WORD context for the Decryptor tier.
        // Decryptor(word) requirement is checked by checking each
        // caller-held Decryptor — but for top-level "must hold decryptor"
        // we treat it as Decryptor(empty) sentinel which won't match.
        // Operators should specify Viewer/Reader/Signer/Verifier here.
        "decryptor" => None,
        "signer" => Some(Capability::Signer(KeyFp::from_bytes([0u8; 32]))),
        "verifier" => Some(Capability::Verifier(KeyFp::from_bytes([0u8; 32]))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::WordId;

    fn policy_with_trust_roots(roots: &[&str]) -> CapPolicy {
        CapPolicy {
            chain: ChainPolicy {
                trust_roots: roots.iter().map(|s| s.to_string()).collect(),
                require_monotonic_timestamps: false,
            },
            words: Vec::new(),
        }
    }

    #[test]
    fn empty_trust_roots_accept_everything() {
        let p = policy_with_trust_roots(&[]);
        let signer: SignerId =
            "ed25519:9f3a7b0000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        assert!(p.trust_root_allows(&signer));
    }

    #[test]
    fn trust_roots_check_is_case_insensitive() {
        let p = policy_with_trust_roots(&[
            "Ed25519:9F3A7B0000000000000000000000000000000000000000000000000000000000",
        ]);
        let signer: SignerId =
            "ed25519:9f3a7b0000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        assert!(p.trust_root_allows(&signer));
    }

    #[test]
    fn trust_roots_rejects_unlisted_signer() {
        let p = policy_with_trust_roots(&[
            "ed25519:aaaa000000000000000000000000000000000000000000000000000000000000",
        ]);
        let signer: SignerId =
            "ed25519:bbbb000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap();
        assert!(!p.trust_root_allows(&signer));
    }

    #[test]
    fn check_word_capability_passes_when_held() {
        let p = CapPolicy {
            chain: ChainPolicy::default(),
            words: vec![WordPolicy {
                name: "Agent_007".into(),
                required_capability: "viewer".into(),
                accepted_recipients: Vec::new(),
            }],
        };
        let held = CapabilitySet::viewing();
        assert!(p.check_word_capability("Agent_007", &held).is_ok());
    }

    #[test]
    fn check_word_capability_fails_when_missing() {
        let p = CapPolicy {
            chain: ChainPolicy::default(),
            words: vec![WordPolicy {
                name: "Agent_007".into(),
                required_capability: "reader".into(),
                accepted_recipients: Vec::new(),
            }],
        };
        // Empty capability set (no Viewer even) — fails Reader.
        let held = CapabilitySet::empty();
        let err = p.check_word_capability("Agent_007", &held).unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn unknown_word_passes() {
        let p = CapPolicy::default();
        let held = CapabilitySet::viewing();
        assert!(p.check_word_capability("UNLISTED", &held).is_ok());
    }

    #[test]
    fn unknown_required_capability_is_configuration_error() {
        let p = CapPolicy {
            chain: ChainPolicy::default(),
            words: vec![WordPolicy {
                name: "X".into(),
                required_capability: "superuser".into(),
                accepted_recipients: Vec::new(),
            }],
        };
        let held = CapabilitySet::viewing();
        let err = p.check_word_capability("X", &held).unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
        assert!(err.to_string().contains("unknown capability"));
    }

    #[test]
    fn parses_full_policy_document() {
        let s = r#"
[chain]
trust_roots = ["ed25519:9f3a7b0000000000000000000000000000000000000000000000000000000000"]
require_monotonic_timestamps = true

[[word]]
name = "Agent_007"
required_capability = "Decryptor"
accepted_recipients = ["ml-kem:1c8d2e0000000000000000000000000000000000000000000000000000000000"]
"#;
        let p = CapPolicy::from_toml_str(s).unwrap();
        assert_eq!(
            p.chain.trust_roots,
            vec!["ed25519:9f3a7b0000000000000000000000000000000000000000000000000000000000"]
        );
        assert!(p.chain.require_monotonic_timestamps);
        assert_eq!(p.words.len(), 1);
        assert_eq!(p.words[0].name, "Agent_007");
        // Decryptor as a top-level required_capability isn't
        // well-defined; check_word_capability surfaces this as a
        // config error rather than silently passing.
        let held = CapabilitySet::viewing().with_decryptor_for_test();
        assert!(p.check_word_capability("Agent_007", &held).is_err());
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let s = "chian = {}\n";
        assert!(CapPolicy::from_toml_str(s).is_err());
    }

    // Test-only helper extension — kept local so the production
    // CapabilitySet API doesn't grow a back door.
    trait CapSetExt {
        fn with_decryptor_for_test(self) -> Self;
    }
    impl CapSetExt for CapabilitySet {
        fn with_decryptor_for_test(mut self) -> Self {
            self.insert(Capability::Decryptor(WordId::new("Agent_007")));
            self
        }
    }
}
