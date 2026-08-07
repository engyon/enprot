# 34 — Capability policy as rule data (OCP for policy rules)

**Priority**: P2
**Status**: specified

## Problem

`src/cappolicy.rs::CapPolicy` hardcodes each policy rule as a method:

```rust
impl CapPolicy {
    pub fn check_word_capability(&self, word: &str, held: &CapabilitySet) -> Result<()> { /* ... */ }
    pub fn trust_root_allows(&self, signer: &SignerId) -> bool { /* ... */ }
    // ...
}
```

Adding a new rule type (e.g. "require multi-sig for HIGH-SECURITY words")
requires modifying `CapPolicy` itself — a violation of the **Open/Closed
Principle**. The policy is **code**, not **data**.

## Goals

- Policy rules become a `Vec<Rule>` where each `Rule` is `(Condition, Action)`.
- Adding a new rule type = adding a TOML entry + a new `Condition` variant.
  No changes to the policy-evaluation engine.
- The engine is closed for modification; rules are open for extension.
- Policy files are **fully declarative** — no embedded code, no script eval.

## Design

### Rule model

```rust
// src/cappolicy.rs (extended)

/// A single policy rule. Conditions are evaluated in order; first
/// match wins (allow or deny). A rule with no condition is the
/// default (always matches).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub condition: Condition,
    pub action: Action,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "params")]
pub enum Condition {
    /// WORD name matches a regex.
    WordMatches { pattern: String },
    /// Signer fingerprint matches a trust root.
    SignerInTrustRoot { trust_root: String },
    /// Operation is one of {encrypt, decrypt, store, fetch}.
    OperationIs { ops: Vec<String> },
    /// Anchor has at least N signatures.
    MinSignatures { n: usize },
    /// Always matches (default rule).
    Always,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Allow,
    Deny { reason: String },
    Require { capability: String },
}

pub struct CapPolicy {
    rules: Vec<Rule>,
    trust_roots: BTreeMap<String, SignerId>,
    chain: ChainPolicy,
}

impl CapPolicy {
    /// Evaluate the policy against a request. First matching rule
    /// wins. If no rule matches, default to Allow (open) — callers
    /// who want default-deny add an `Always → Deny` catch-all.
    pub fn evaluate(&self, req: &Request) -> Decision {
        for rule in &self.rules {
            if rule.condition.matches(req, &self.trust_roots) {
                return match rule.action {
                    Action::Allow => Decision::Allow,
                    Action::Deny { ref reason } => Decision::Deny(reason.clone()),
                    Action::Require { ref capability } => {
                        if req.held_capabilities.contains(capability) {
                            Decision::Allow
                        } else {
                            Decision::Deny(format!("missing required capability: {capability}"))
                        }
                    }
                };
            }
        }
        Decision::Allow
    }
}

pub struct Request {
    pub word: String,
    pub operation: Operation,
    pub signer: Option<SignerId>,
    pub signatures: usize,
    pub held_capabilities: HashSet<String>,
}

pub enum Decision {
    Allow,
    Deny(String),
}
```

### Condition matching (the trait that makes it extensible)

```rust
trait ConditionMatch {
    fn matches(&self, req: &Request, trust_roots: &BTreeMap<String, SignerId>) -> bool;
}

impl ConditionMatch for Condition {
    fn matches(&self, req: &Request, trust_roots: &BTreeMap<String, SignerId>) -> bool {
        match self {
            Self::WordMatches { pattern } => Regex::new(pattern).unwrap().is_match(&req.word),
            Self::SignerInTrustRoot { trust_root } => {
                req.signer.as_ref()
                    .and_then(|s| trust_roots.get(trust_root))
                    .map(|tr| tr == s)
                    .unwrap_or(false)
            }
            Self::OperationIs { ops } => ops.iter().any(|op| *op == req.operation.label()),
            Self::MinSignatures { n } => req.signatures >= *n,
            Self::Always => true,
        }
    }
}
```

### TOML surface

```toml
# .enprot/policy.toml
[[rule]]
condition = { kind = "WordMatches", params = { pattern = "^(TOP_SECRET|CRYPTO)$" } }
action = { Require = { capability = "encrypt-top-secret" } }

[[rule]]
condition = { kind = "SignerInTrustRoot", params = { trust_root = "prod-issuer" } }
action = "Allow"

[[rule]]
condition = "Always"
action = { Deny = { reason = "no matching rule" } }

[trust_roots.prod-issuer]
fingerprint = "ed25519:abcd1234..."
```

### Backward compatibility

Existing `CapPolicy::load_file` continues to work. The legacy TOML
schema (a flat list of `word_rules`) is auto-converted to the new
`Vec<Rule>` at load time. New consumers use the rule schema directly.

## Implementation plan

1. Add `Rule`, `Condition`, `Action`, `Request`, `Decision` types.
2. Implement `CapPolicy::evaluate` + the `ConditionMatch` trait.
3. Convert the existing `check_word_capability` / `trust_root_allows`
   internal callers to use `evaluate`.
4. Add a migration layer in `CapPolicy::load_file` that detects the
   legacy schema and converts it.
5. Document the new rule schema in `docs/cap-policy.md`.
6. Add unit tests for each `Condition` variant + combination tests.

## Test plan

- [ ] Each `Condition` variant has a positive + negative unit test.
- [ ] Rules are evaluated in order; first match wins.
- [ ] Legacy TOML files load and produce equivalent `Vec<Rule>`.
- [ ] A new `Condition` variant can be added without touching the
  evaluation engine (compile-time check: the trait is sealed).

## Out of scope

- Boolean composition of conditions (AND/OR/NOT) — defer until a real
  use case appears. The current model handles composition via rule
  ordering + multiple rules.
- Per-rule audit logging — covered by TODO.complete/31 (tracing).
- Hot reload of policy files at runtime.
