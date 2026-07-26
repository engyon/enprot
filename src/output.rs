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

//! Structured output for inspection subcommands (TODO.roadmap/41).
//!
//! Every JSON payload is wrapped in an [`Envelope`] that stamps the
//! `$schema` field, so consumers can pin a schema version independent
//! of the enprot release. The text format remains the default — JSON
//! is opt-in via `--format json`.
//!
//! DTOs are deliberately concrete: each inspection subcommand has its
//! own `*Output` struct rather than reusing the internal types, so the
//! wire schema stays stable when internal representations evolve.

use serde::Serialize;

/// Schema version stamped on every JSON envelope. Bump when a breaking
/// shape change is introduced; keep stable for additive changes.
pub const SCHEMA: &str = "enprot/v1";

/// Output rendering mode. `Text` is the historical default; `Json`
/// emits a stable, machine-readable envelope.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Wrapper that stamps `$schema` on every JSON payload.
#[derive(Serialize)]
pub struct Envelope<'a, T: Serialize> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    #[serde(flatten)]
    data: &'a T,
}

/// Render `data` as a JSON envelope with the current schema tag.
pub fn to_json<T: Serialize>(data: &T) -> crate::error::Result<String> {
    let env = Envelope {
        schema: SCHEMA,
        data,
    };
    serde_json::to_string_pretty(&env).map_err(crate::error::Error::json)
}

/// One capability in a `capabilities --format json` payload.
#[derive(Serialize)]
pub struct CapabilityDto {
    pub tier: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_fp: Option<String>,
}

#[derive(Serialize)]
pub struct CapabilitiesOutput {
    pub capabilities: Vec<CapabilityDto>,
}

/// A node within a `list --format json` file listing. Mirrors the
/// structure of [`crate::etree::TextNode`] but only carries the
/// inspection-relevant fields. `Plain`/`Data` nodes are omitted (they
/// don't carry directive information worth listing).
#[derive(Serialize)]
pub struct ListNode {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub word: String,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pbkdf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<ListNode>,
}

#[derive(Serialize)]
pub struct FileListing {
    pub path: String,
    pub nodes: Vec<ListNode>,
}

#[derive(Serialize)]
pub struct ListOutput {
    pub files: Vec<FileListing>,
}

#[derive(Serialize)]
pub struct ForkPoint {
    pub anchor: String,
    pub parents: Vec<String>,
}

#[derive(Serialize)]
pub struct VerifyError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    pub message: String,
}

#[derive(Serialize)]
pub struct VerifyChainFileReport {
    pub path: String,
    pub ok: bool,
    pub anchors_total: usize,
    pub signers: Vec<String>,
    pub forks: Vec<ForkPoint>,
    pub errors: Vec<VerifyError>,
}

#[derive(Serialize)]
pub struct VerifyChainOutput {
    pub ok: bool,
    pub files: Vec<VerifyChainFileReport>,
}

/// One unresolved CONFLICT block. `ours_nodes` / `theirs_nodes`
/// are node counts; the contents are intentionally not serialized
/// — they may contain ciphertext and shouldn't leak through JSON.
#[derive(Serialize)]
pub struct ConflictEntry {
    pub word: String,
    pub ours_nodes: usize,
    pub theirs_nodes: usize,
}

#[derive(Serialize)]
pub struct ConflictsOutput {
    pub conflicts: Vec<ConflictEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_stamps_schema() {
        let caps = CapabilitiesOutput {
            capabilities: vec![CapabilityDto {
                tier: "viewer",
                word: None,
                key_fp: None,
            }],
        };
        let s = to_json(&caps).unwrap();
        assert!(s.contains("\"$schema\": \"enprot/v1\""), "got: {s}");
        assert!(s.contains("\"tier\": \"viewer\""));
    }

    #[test]
    fn capability_dto_omits_empty_optional_fields() {
        let dto = CapabilityDto {
            tier: "viewer",
            word: None,
            key_fp: None,
        };
        let s = serde_json::to_string(&dto).unwrap();
        assert!(!s.contains("word"));
        assert!(!s.contains("key_fp"));
    }

    #[test]
    fn list_node_omits_empty_children() {
        let n = ListNode {
            kind: "encrypted",
            word: "Agent_007".into(),
            depth: 0,
            cipher: Some("aes-256-siv".into()),
            pbkdf: None,
            cas: None,
            signer: None,
            payload: None,
            children: vec![],
        };
        let s = serde_json::to_string(&n).unwrap();
        assert!(!s.contains("children"), "got: {s}");
    }

    #[test]
    fn verify_chain_output_includes_overall_ok() {
        let out = VerifyChainOutput {
            ok: true,
            files: vec![VerifyChainFileReport {
                path: "a.ept".into(),
                ok: true,
                anchors_total: 1,
                signers: vec!["ed25519:abcd".into()],
                forks: vec![],
                errors: vec![],
            }],
        };
        let s = to_json(&out).unwrap();
        assert!(s.contains("\"ok\": true"));
        assert!(s.contains("\"anchors_total\": 1"));
    }
}
