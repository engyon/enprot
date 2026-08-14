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

//! Capability policy enforcement (TODO.roadmap/46, TODO.complete/34).
//!
//! A `CapPolicy` is a TOML document with three sections:
//!
//! - `[chain]` — trust roots and timestamp monotonicity (the chain
//!   verification axis; consulted by `verify-chain`).
//! - `[[word]]` — the legacy per-WORD section. Retained for backward
//!   compatibility and for introspection (`enprot cap` surfaces
//!   `accepted_recipients` from it).
//! - `[[rule]]` — the declarative rule section. Each rule is a
//!   `(condition, action)` pair; rules evaluate in document order and
//!   the first match decides. No match = allow (open default; add an
//!   `always → deny` catch-all for default-deny).
//!
//! Word-capability decisions flow through the **rule engine**
//! ([`CapPolicy::evaluate`]): both `[[word]]` and `[[rule]]` entries
//! are compiled into `Vec<Rule>` at load time, and
//! [`CapPolicy::check_word_capability`] is a thin wrapper over the
//! engine. The engine is closed for modification — adding a rule
//! *kind* is a new `Condition`/`Action` variant plus its match arm;
//! the evaluation loop never changes (OCP). Capability names are
//! validated eagerly at load, so an invalid policy fails at
//! `--policy-file` load rather than mid-encrypt (fail fast).
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
///
/// Invariant: `rules` is the compiled decision model and is built
/// only by [`CapPolicy::compile`] at load time, from `words` +
/// `rule_dtos`. `words` stays a field (not folded into rules) because
/// introspection reads `accepted_recipients` from it — the decision
/// path reads only `rules`; the introspection path reads only
/// `words`. One source at load, two projections after (MECE).
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
    /// Declarative `[[rule]]` tables (wire form). Compiled into
    /// `rules` at load; kept for introspection and round-tripping.
    #[serde(default, rename = "rule")]
    rule_dtos: Vec<RuleDto>,
    /// Compiled decision model. Populated by `compile`.
    #[serde(skip)]
    rules: Vec<Rule>,
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

// ---------------------------------------------------------------------
// Rule model (TODO.complete/34)
// ---------------------------------------------------------------------

/// One declarative rule: when `condition` matches the request,
/// `action` decides. The wire (TOML) form is [`RuleDto`]; this is the
/// compiled model the engine evaluates.
#[derive(Debug, Clone)]
struct Rule {
    condition: Condition,
    action: Action,
}

/// What a rule matches on. Exhaustive `match` in [`Condition::matches`]
/// means a new variant cannot be added without extending the engine's
/// match arm — the set of conditions is closed, each condition is
/// self-contained.
#[derive(Debug, Clone)]
enum Condition {
    /// Matches when the requested WORD is exactly `name`.
    WordIs { name: String },
    /// Matches every request (catch-all).
    Always,
}

impl Condition {
    fn matches(&self, req: &Request<'_>) -> bool {
        match self {
            Condition::WordIs { name } => req.word == name,
            Condition::Always => true,
        }
    }
}

/// What happens when a rule's condition matches. `RequireCapability`
/// carries the *parsed* [`Capability`] — no string parsing at
/// decision time.
#[derive(Debug, Clone)]
enum Action {
    Allow,
    RequireCapability(Capability),
    Deny { reason: String },
}

impl Action {
    fn decide(&self, req: &Request<'_>) -> Decision {
        match self {
            Action::Allow => Decision::Allow,
            Action::RequireCapability(cap) => {
                if req.held.contains(cap) {
                    Decision::Allow
                } else {
                    Decision::Deny {
                        rule: "word.required_capability".into(),
                        context: format!(
                            "WORD {} requires {}; caller does not hold it",
                            req.word,
                            capability_label(cap)
                        ),
                    }
                }
            }
            Action::Deny { reason } => Decision::Deny {
                rule: "rule.deny".into(),
                context: reason.clone(),
            },
        }
    }
}

/// The outcome of evaluating the rule list against one request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny { rule: String, context: String },
}

impl Decision {
    fn into_result(self) -> Result<()> {
        match self {
            Decision::Allow => Ok(()),
            Decision::Deny { rule, context } => Err(Error::PolicyViolation { rule, context }),
        }
    }
}

/// Everything the engine knows about the caller's request. One struct
/// so future conditions (signer, operation, signature count) extend
/// the request rather than grow the method surface.
#[derive(Debug)]
struct Request<'a> {
    word: &'a str,
    held: &'a CapabilitySet,
}

/// Canonical label of a parsed capability for error messages.
/// Signer/Verifier carry key fingerprints; the label uses the tier
/// name so messages match the TOML vocabulary.
fn capability_label(cap: &Capability) -> String {
    match cap {
        Capability::Viewer => "viewer".into(),
        Capability::Reader => "reader".into(),
        Capability::Decryptor(_) => "decryptor".into(),
        Capability::Signer(_) => "signer".into(),
        Capability::Verifier(_) => "verifier".into(),
    }
}

// ---------------------------------------------------------------------
// Rule wire form (serde)
// ---------------------------------------------------------------------

/// `[[rule]]` table. Internally-tagged enums below keep the TOML
/// declarative and self-describing:
///
/// ```toml
/// [[rule]]
/// condition = { kind = "word", word = "Agent_007" }
/// action = { kind = "require", capability = "viewer" }
///
/// [[rule]]
/// condition = { kind = "always" }
/// action = { kind = "deny", reason = "no matching rule" }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RuleDto {
    condition: ConditionDto,
    action: ActionDto,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum ConditionDto {
    Word { word: String },
    Always,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum ActionDto {
    Allow,
    Require { capability: String },
    Deny { reason: String },
}

impl RuleDto {
    /// Compile the wire form into the decision model. Capability
    /// strings are parsed here — an unknown name fails at load.
    fn to_rule(&self) -> Result<Rule> {
        let condition = match &self.condition {
            ConditionDto::Word { word } => Condition::WordIs { name: word.clone() },
            ConditionDto::Always => Condition::Always,
        };
        let action = match &self.action {
            ActionDto::Allow => Action::Allow,
            ActionDto::Require { capability } => {
                Action::RequireCapability(parse_capability(capability).ok_or_else(|| {
                    Error::PolicyViolation {
                        rule: "rule.action.require".into(),
                        context: format!("unknown capability '{capability}' in [[rule]]"),
                    }
                })?)
            }
            ActionDto::Deny { reason } => Action::Deny {
                reason: reason.clone(),
            },
        };
        Ok(Rule { condition, action })
    }
}

impl CapPolicy {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let parsed: CapPolicy =
            toml::from_str(s).map_err(|e| Error::Json(format!("policy parse: {e}")))?;
        parsed.compile()
    }

    pub fn load_file(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_toml_str(&s)
    }

    /// Compile the wire sections into the decision model. `[[word]]`
    /// entries compile first (preserving their historical
    /// first-declared-wins lookup), then `[[rule]]` entries in
    /// document order. Called only by [`CapPolicy::from_toml_str`].
    fn compile(mut self) -> Result<Self> {
        let mut rules = Vec::with_capacity(self.words.len() + self.rule_dtos.len());
        for w in &self.words {
            let cap =
                parse_capability(&w.required_capability).ok_or_else(|| Error::PolicyViolation {
                    rule: "word.required_capability".into(),
                    context: format!(
                        "unknown capability '{}' for WORD {}",
                        w.required_capability, w.name
                    ),
                })?;
            rules.push(Rule {
                condition: Condition::WordIs {
                    name: w.name.clone(),
                },
                action: Action::RequireCapability(cap),
            });
        }
        for dto in &self.rule_dtos {
            rules.push(dto.to_rule()?);
        }
        self.rules = rules;
        Ok(self)
    }

    /// Evaluate the rule list against a request. First match wins;
    /// no match = allow (open default).
    fn evaluate(&self, req: &Request<'_>) -> Decision {
        for rule in &self.rules {
            if rule.condition.matches(req) {
                return rule.action.decide(req);
            }
        }
        Decision::Allow
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
    /// Thin wrapper over the rule engine; the decision logic lives
    /// in [`Action::decide`], not here.
    pub fn check_word_capability(&self, word: &str, held: &CapabilitySet) -> Result<()> {
        self.evaluate(&Request { word, held }).into_result()
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

    /// Build a compiled policy from legacy `[[word]]` entries (the
    /// same path `from_toml_str` takes, so tests exercise the real
    /// invariant: struct → compile → rules).
    fn policy_with_words(words: Vec<WordPolicy>) -> CapPolicy {
        CapPolicy {
            chain: ChainPolicy::default(),
            words,
            rule_dtos: Vec::new(),
            rules: Vec::new(),
        }
        .compile()
        .unwrap()
    }

    fn policy_with_trust_roots(roots: &[&str]) -> CapPolicy {
        CapPolicy {
            chain: ChainPolicy {
                trust_roots: roots.iter().map(|s| s.to_string()).collect(),
                require_monotonic_timestamps: false,
            },
            words: Vec::new(),
            rule_dtos: Vec::new(),
            rules: Vec::new(),
        }
        .compile()
        .unwrap()
    }

    fn word(name: &str, cap: &str) -> WordPolicy {
        WordPolicy {
            name: name.into(),
            required_capability: cap.into(),
            accepted_recipients: Vec::new(),
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
        let p = policy_with_words(vec![word("Agent_007", "viewer")]);
        let held = CapabilitySet::viewing();
        assert!(p.check_word_capability("Agent_007", &held).is_ok());
    }

    #[test]
    fn check_word_capability_fails_when_missing() {
        let p = policy_with_words(vec![word("Agent_007", "reader")]);
        // Empty capability set (no Viewer even) — fails Reader.
        let held = CapabilitySet::empty();
        let err = p.check_word_capability("Agent_007", &held).unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
        assert!(err.to_string().contains("requires reader"), "got: {err}");
    }

    #[test]
    fn unknown_word_passes() {
        let p = policy_with_words(vec![word("Agent_007", "viewer")]);
        let held = CapabilitySet::viewing();
        assert!(p.check_word_capability("UNLISTED", &held).is_ok());
    }

    #[test]
    fn unknown_required_capability_is_a_load_error() {
        // Fail fast: an invalid capability name in [[word]] is
        // rejected when the policy loads, not at first use.
        let p = CapPolicy::from_toml_str(
            r#"
            [[word]]
            name = "X"
            required_capability = "superuser"
            "#,
        );
        let err = p.unwrap_err();
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
required_capability = "viewer"
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
        // Introspection still sees the recipient whitelist.
        assert_eq!(p.words[0].accepted_recipients.len(), 1);
        // And the compiled rule enforces the capability.
        assert!(
            p.check_word_capability("Agent_007", &CapabilitySet::viewing())
                .is_ok()
        );
    }

    #[test]
    fn decryptor_as_required_capability_is_a_load_error() {
        // Decryptor requires a WORD; as a top-level requirement it
        // isn't well-defined. Historically a check-time error; now
        // rejected at load (fail fast).
        let err = CapPolicy::from_toml_str(
            r#"
            [[word]]
            name = "Agent_007"
            required_capability = "Decryptor"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let s = "chian = {}\n";
        assert!(CapPolicy::from_toml_str(s).is_err());
    }

    // ------------------------------------------------------------------
    // Rule engine (TODO.complete/34)
    // ------------------------------------------------------------------

    fn rule_toml(condition: &str, action: &str) -> String {
        format!("[[rule]]\ncondition = {condition}\naction = {action}\n")
    }

    #[test]
    fn rule_require_enforces_capability() {
        let p = CapPolicy::from_toml_str(&rule_toml(
            r#"{ kind = "word", word = "Agent_007" }"#,
            r#"{ kind = "require", capability = "viewer" }"#,
        ))
        .unwrap();
        assert!(
            p.check_word_capability("Agent_007", &CapabilitySet::viewing())
                .is_ok()
        );
        let err = p
            .check_word_capability("Agent_007", &CapabilitySet::empty())
            .unwrap_err();
        assert!(err.to_string().contains("requires viewer"));
    }

    #[test]
    fn rule_word_condition_is_exact() {
        let p = CapPolicy::from_toml_str(&rule_toml(
            r#"{ kind = "word", word = "Agent_007" }"#,
            r#"{ kind = "deny", reason = "nope" }"#,
        ))
        .unwrap();
        assert!(
            p.check_word_capability("Agent_008", &CapabilitySet::empty())
                .is_ok()
        );
        assert!(
            p.check_word_capability("Agent_007", &CapabilitySet::empty())
                .is_err()
        );
    }

    #[test]
    fn rule_always_condition_matches_every_word() {
        let p = CapPolicy::from_toml_str(&rule_toml(
            r#"{ kind = "always" }"#,
            r#"{ kind = "deny", reason = "default deny" }"#,
        ))
        .unwrap();
        for w in ["a", "b", "anything"] {
            assert!(p.check_word_capability(w, &CapabilitySet::empty()).is_err());
        }
    }

    #[test]
    fn rule_allow_unblocks_a_word_under_default_deny() {
        let toml = r#"
[[rule]]
condition = { kind = "word", word = "PUBLIC" }
action = { kind = "allow" }

[[rule]]
condition = { kind = "always" }
action = { kind = "deny", reason = "no matching rule" }
"#;
        let p = CapPolicy::from_toml_str(toml).unwrap();
        assert!(
            p.check_word_capability("PUBLIC", &CapabilitySet::empty())
                .is_ok()
        );
        let err = p
            .check_word_capability("SECRET", &CapabilitySet::empty())
            .unwrap_err();
        assert!(err.to_string().contains("no matching rule"));
    }

    #[test]
    fn first_matching_rule_wins() {
        let toml = r#"
[[rule]]
condition = { kind = "word", word = "W" }
action = { kind = "allow" }

[[rule]]
condition = { kind = "always" }
action = { kind = "deny", reason = "second" }
"#;
        let p = CapPolicy::from_toml_str(toml).unwrap();
        // The word rule matches first and allows, even though the
        // catch-all would deny.
        assert!(
            p.check_word_capability("W", &CapabilitySet::empty())
                .is_ok()
        );
        // Other words fall to the catch-all.
        assert!(
            p.check_word_capability("X", &CapabilitySet::empty())
                .is_err()
        );
    }

    #[test]
    fn no_rules_is_open() {
        let p = CapPolicy::from_toml_str("").unwrap();
        assert!(
            p.check_word_capability("ANY", &CapabilitySet::empty())
                .is_ok()
        );
    }

    #[test]
    fn word_rules_take_precedence_over_rule_tables() {
        // Compile order: [[word]] entries first, [[rule]] entries
        // after — documented behavior. A word entry therefore wins
        // over a later always-deny.
        let toml = r#"
[[word]]
name = "Agent_007"
required_capability = "viewer"

[[rule]]
condition = { kind = "always" }
action = { kind = "deny", reason = "catch-all" }
"#;
        let p = CapPolicy::from_toml_str(toml).unwrap();
        assert!(
            p.check_word_capability("Agent_007", &CapabilitySet::viewing())
                .is_ok(),
            "word rule should decide before the catch-all"
        );
        assert!(
            p.check_word_capability("OTHER", &CapabilitySet::empty())
                .is_err()
        );
    }

    #[test]
    fn unknown_capability_in_rule_is_a_load_error() {
        let err = CapPolicy::from_toml_str(&rule_toml(
            r#"{ kind = "always" }"#,
            r#"{ kind = "require", capability = "superuser" }"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown capability"));
    }

    #[test]
    fn unknown_field_in_rule_table_rejected() {
        let err = CapPolicy::from_toml_str(
            r#"
            [[rule]]
            condition = { kind = "always" }
            action = { kind = "allow" }
            priority = 1
            "#,
        );
        assert!(err.is_err(), "deny_unknown_fields must reject 'priority'");
    }

    #[test]
    fn unknown_condition_kind_rejected() {
        let err = CapPolicy::from_toml_str(&rule_toml(
            r#"{ kind = "regex", pattern = ".*" }"#,
            r#"{ kind = "allow" }"#,
        ));
        assert!(err.is_err());
    }

    #[test]
    fn signer_and_verifier_requirements_use_sentinel_fingerprints() {
        // Compiling 'signer'/'verifier' produces the zero-fingerprint
        // sentinel, which a real holder never matches — preserved
        // legacy behavior (documented in parse_capability).
        let p = policy_with_words(vec![word("W", "signer")]);
        assert!(
            p.check_word_capability("W", &CapabilitySet::empty())
                .is_err()
        );
    }
}
