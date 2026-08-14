<!-- Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com). -->
<!--
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
-->

# Capability Policy

**Status**: living document; schema versioned by the `CapPolicy` TOML surface.

A capability policy is a TOML document loaded via `enprot --policy-file
<policy.toml>`. It has three sections:

| Section | Purpose | Consulted by |
|---|---|---|
| `[chain]` | Trust roots, timestamp monotonicity | `verify-chain` |
| `[[word]]` | Legacy per-WORD capability requirements | `encrypt`, `enprot cap` |
| `[[rule]]` | Declarative rules (condition → action) | `encrypt`, `enprot cap` |

The policy is **fail fast**: capability names are validated when the
document loads. An invalid name aborts the run at `--policy-file` load,
not at the first encrypt that touches the WORD.

## `[chain]` — chain verification axis

```toml
[chain]
# When non-empty, verify-chain rejects any anchor whose signer is
# not in this list. Empty means "no whitelist".
trust_roots = [
  "ed25519:9f3a7b0000000000000000000000000000000000000000000000000000000000",
]
# When true, anchor timestamps must strictly increase along parent edges.
require_monotonic_timestamps = true
```

## `[[word]]` — legacy per-WORD requirements

```toml
[[word]]
name = "Agent_007"
required_capability = "viewer"   # viewer | reader | signer | verifier
accepted_recipients = [          # ML-KEM recipient whitelist (introspection-only today)
  "ml-kem:1c8d2e0000000000000000000000000000000000000000000000000000000000",
]
```

`decryptor` is not valid as a `required_capability` — decryption
rights are inherently per-WORD and expressed by the caller's key
material, not by a policy tier. A document using it fails to load.

## `[[rule]]` — the rule engine

Each rule is a `(condition, action)` pair. Rules evaluate in document
order; **the first matching rule decides**; when no rule matches, the
decision is *allow* (open default). Add an `always → deny` catch-all
for a default-deny posture.

```toml
# Require a capability for one WORD.
[[rule]]
condition = { kind = "word", word = "TOP_SECRET" }
action = { kind = "require", capability = "verifier" }

# Unconditionally allow a public WORD.
[[rule]]
condition = { kind = "word", word = "PUBLIC" }
action = { kind = "allow" }

# Default-deny everything else.
[[rule]]
condition = { kind = "always" }
action = { kind = "deny", reason = "no matching rule" }
```

### Conditions

| `kind` | Fields | Matches when |
|---|---|---|
| `word` | `word` | the requested WORD is exactly `word` |
| `always` | — | every request (catch-all) |

### Actions

| `kind` | Fields | Effect |
|---|---|---|
| `allow` | — | allow the request |
| `require` | `capability` | allow iff the caller holds `capability` (`viewer`, `reader`, `signer`, `verifier`) |
| `deny` | `reason` | deny with `reason` surfaced in the error |

### Evaluation order with `[[word]]` entries

`[[word]]` entries compile into rules **before** `[[rule]]` entries,
so a `[[word]]` requirement decides before any `[[rule]]` catch-all.
Within each section, document order applies.

## Semantics summary

- First match wins, per section order above.
- No match → allow.
- A `require` failure reports `WORD <w> requires <capability>; caller
  does not hold it` as a `PolicyViolation`.
- Unknown fields anywhere in the document are rejected
  (`deny_unknown_fields`) — typos fail at load, never silently pass.

## Extending the engine

The evaluation loop is closed for modification. A new rule kind is:

1. a new `Condition` (or `Action`) variant plus its match arm, and
2. its serde counterpart in the wire enums.

The loop itself never changes. See `src/cappolicy.rs`.
