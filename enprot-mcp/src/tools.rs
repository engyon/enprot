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

//! The tool catalog (TODO.complete/57). Each tool: an rmcp [`Tool`]
//! (name, description, JSON schema) plus a typed argument struct plus
//! a run function that policy-checks, builds the CLI argv, and maps
//! the CLI's output to a structured MCP result.
//!
//! Read-only tools return the CLI's `--format json` output as
//! `structuredContent` verbatim (the CLI's JSON shapes are the
//! contract); mutating tools return a compact summary object. On CLI
//! failure the result carries `is_error` with the CLI's stderr — the
//! agent sees the actionable message, not a stack trace.

use std::collections::BTreeMap;
use std::path::Path;

use rmcp::model::{CallToolResult, ContentBlock, ErrorData, JsonObject, Tool};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::driver;
use crate::policy::{Access, McpPolicy};

// ---------------------------------------------------------------- args

#[derive(Deserialize)]
struct PathArg {
    path: String,
}

#[derive(Deserialize)]
struct InspectArg {
    path: String,
}

#[derive(Deserialize)]
struct EncryptArg {
    path: String,
    /// WORD segments to operate on.
    words: Vec<String>,
    /// word -> password. Exactly one password per WORD; use
    /// `key_file` for KEM/escrow blocks instead.
    #[serde(default)]
    passwords: BTreeMap<String, String>,
    /// Cipher algorithm (default: policy default, currently
    /// aes-256-gcm-siv-det).
    #[serde(default)]
    cipher: Option<String>,
    /// Recovery pubkeys (PEM paths) for escrow mode; requires a
    /// non-det cipher.
    #[serde(default)]
    recovery_keys: Vec<String>,
    /// Also store the ciphertext to CAS (encrypt-store semantics).
    #[serde(default)]
    store: bool,
    /// Decrypt with a recovery/recipient privkey instead of
    /// passwords (decrypt tool only).
    #[serde(default)]
    key_file: Option<String>,
}

#[derive(Deserialize)]
struct VerifyChainArg {
    path: String,
    /// Trusted pubkey PEM paths. Empty = verify against the pubkey
    /// named by each anchor (fails if none matches).
    #[serde(default)]
    trust_roots: Vec<String>,
}

#[derive(Deserialize)]
struct PinArg {
    path: String,
    /// Expected chain-head hash (64 hex chars), from `enprot_snapshot`.
    expected: String,
}

#[derive(Deserialize)]
struct CapCheckArg {
    word: String,
    /// One of: encrypt, decrypt, store, fetch, verify.
    op: String,
}

// ------------------------------------------------------------- helpers

fn schema(properties: Value, required: &[&str]) -> JsonObject {
    let mut map = json!({
        "type": "object",
        "properties": properties,
    });
    if !required.is_empty() {
        map["required"] = json!(required);
    }
    serde_json::from_value(map).expect("static schema is valid JSON")
}

fn text_tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Tool {
    Tool::new(
        name.to_string(),
        description.to_string(),
        schema(properties, required),
    )
}

fn denied_result(denied: crate::policy::Denied) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(format!(
        "policy denied {} of {}: {}",
        match denied.access {
            Access::Read => "read",
            Access::Write => "write",
        },
        denied.path.display(),
        denied.reason
    ))]);
    result.is_error = Some(true);
    result
}

macro_rules! check_policy {
    ($policy:expr, $path:expr, $access:expr) => {
        if let Err(denied) = $policy.check(Path::new($path), $access) {
            return Ok(denied_result(denied));
        }
    };
}

/// Run the CLI and shape the outcome. `json` tools parse stdout into
/// structured content; text tools pass it through.
fn run_cli(args: &[String], structured: bool) -> Result<CallToolResult, ErrorData> {
    let outcome = tokio::task::block_in_place(|| driver::run(args))
        .map_err(|e| ErrorData::internal_error(format!("failed to run enprot: {e}"), None))?;
    if !outcome.success {
        let mut result = CallToolResult::success(vec![ContentBlock::text(outcome.stderr.trim())]);
        result.is_error = Some(true);
        return Ok(result);
    }
    let mut result = if structured {
        let parsed: Value = serde_json::from_str(outcome.stdout.trim()).map_err(|e| {
            ErrorData::internal_error(
                format!("enprot emitted invalid JSON: {e}\n{}", outcome.stdout),
                None,
            )
        })?;
        CallToolResult::success(vec![ContentBlock::text(outcome.stdout.trim())])
            .with_structured(parsed)
    } else {
        CallToolResult::success(vec![ContentBlock::text(outcome.stdout.trim())])
    };
    if outcome.stdout.trim().is_empty() {
        // Quiet success (e.g. snapshot, encrypt in-place): say so.
        result = CallToolResult::success(vec![ContentBlock::text("ok")]);
    }
    Ok(result)
}

trait WithStructured {
    fn with_structured(self, v: Value) -> Self;
}

impl WithStructured for CallToolResult {
    fn with_structured(mut self, v: Value) -> Self {
        self.structured_content = Some(v);
        self
    }
}

fn s(v: &str) -> String {
    v.to_string()
}

// -------------------------------------------------------------- tools

fn inspect(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: InspectArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Read);
    run_cli(
        &[
            "inspect".into(),
            "--format".into(),
            "json".into(),
            s(&a.path),
        ],
        true,
    )
}

fn encrypt(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: EncryptArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Write);
    for k in &a.recovery_keys {
        check_policy!(policy, k, Access::Read);
    }
    let sub = if a.store { "encrypt-store" } else { "encrypt" };
    let mut argv = vec![s(sub)];
    for w in &a.words {
        argv.extend(["-w".into(), s(w)]);
    }
    for (w, p) in &a.passwords {
        argv.extend(["-k".into(), format!("{w}={p}")]);
    }
    if let Some(c) = &a.cipher {
        argv.extend(["--cipher".into(), s(c)]);
    }
    for k in &a.recovery_keys {
        argv.extend(["--recovery-key".into(), s(k)]);
    }
    argv.push(s(&a.path));
    run_cli(&argv, false)
}

fn decrypt(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: EncryptArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Write);
    let mut argv = vec![s("decrypt")];
    for w in &a.words {
        argv.extend(["-w".into(), s(w)]);
    }
    for (w, p) in &a.passwords {
        argv.extend(["-k".into(), format!("{w}={p}")]);
    }
    if let Some(k) = &a.key_file {
        check_policy!(policy, k, Access::Read);
        argv.extend(["--key-file".into(), s(k)]);
    }
    argv.push(s(&a.path));
    run_cli(&argv, false)
}

fn verify(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: PathArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Read);
    run_cli(
        &[
            "verify".into(),
            "--format".into(),
            "json".into(),
            s(&a.path),
        ],
        true,
    )
}

fn verify_chain(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: VerifyChainArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Read);
    for r in &a.trust_roots {
        check_policy!(policy, r, Access::Read);
    }
    let mut argv = vec![s("verify-chain"), "--format".into(), "json".into()];
    for r in &a.trust_roots {
        argv.extend(["--trust-root".into(), s(r)]);
    }
    argv.push(s(&a.path));
    run_cli(&argv, true)
}

fn snapshot(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: PathArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Read);
    // snapshot writes `<file>.snapshot` next to the input.
    let sidecar = format!("{}.snapshot", a.path);
    check_policy!(policy, &sidecar, Access::Write);
    run_cli(&[s("snapshot"), s(&a.path)], false)
}

fn pin(args: &JsonObject, policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: PinArg = parse_args(args)?;
    check_policy!(policy, &a.path, Access::Read);
    run_cli(&[s("pin"), s(&a.expected), s(&a.path)], false)
}

fn cap_show(args: &JsonObject, _policy: &McpPolicy) -> Result<CallToolResult, ErrorData> {
    let a: CapCheckArg = parse_args(args)?;
    run_cli(
        &[
            s("cap"),
            s("check"),
            "--word".into(),
            s(&a.word),
            "--op".into(),
            s(&a.op),
            "--format".into(),
            "json".into(),
        ],
        true,
    )
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &JsonObject) -> Result<T, ErrorData> {
    let value = Value::Object(args.clone());
    serde_json::from_value(value)
        .map_err(|e| ErrorData::invalid_params(format!("invalid tool arguments: {e}"), None))
}

// ------------------------------------------------------------ catalog

pub fn catalog() -> Vec<Tool> {
    vec![
        text_tool(
            "enprot_inspect",
            "Inspect the structure of an EPT file: blocks, chain anchors, conflicts. \
             Read-only. Returns the CLI's JSON structure report.",
            json!({
                "path": { "type": "string", "description": "Path to the .ept file" }
            }),
            &["path"],
        ),
        text_tool(
            "enprot_encrypt",
            "Encrypt WORD segments in a file (in place). Requires the write policy. \
             Supply either `passwords` (word -> password) or nothing for interactive \
             modes; `recovery_keys` enables escrow (needs a non-det cipher).",
            json!({
                "path": { "type": "string" },
                "words": { "type": "array", "items": { "type": "string" },
                           "description": "WORD segments to encrypt" },
                "passwords": { "type": "object",
                               "additionalProperties": { "type": "string" },
                               "description": "word -> password" },
                "cipher": { "type": "string",
                            "description": "e.g. aes-256-siv, aes-256-gcm" },
                "recovery_keys": { "type": "array", "items": { "type": "string" },
                                   "description": "recovery pubkey PEM paths (escrow)" },
                "store": { "type": "boolean", "description": "also store ct to CAS" }
            }),
            &["path", "words"],
        ),
        text_tool(
            "enprot_decrypt",
            "Decrypt WORD segments in a file (in place). Requires the write policy. \
             Supply `passwords` or `key_file` (recovery/recipient privkey).",
            json!({
                "path": { "type": "string" },
                "words": { "type": "array", "items": { "type": "string" } },
                "passwords": { "type": "object",
                               "additionalProperties": { "type": "string" } },
                "key_file": { "type": "string",
                              "description": "recovery or KEM recipient privkey PEM" }
            }),
            &["path", "words"],
        ),
        text_tool(
            "enprot_verify",
            "Verify the structural integrity of an EPT file (markup shape). Read-only.",
            json!({ "path": { "type": "string" } }),
            &["path"],
        ),
        text_tool(
            "enprot_verify_chain",
            "Verify CHAIN anchor signatures and the DAG of a file against trust \
             roots. Read-only. Returns the per-file JSON verification report.",
            json!({
                "path": { "type": "string" },
                "trust_roots": { "type": "array", "items": { "type": "string" },
                                 "description": "trusted pubkey PEM paths" }
            }),
            &["path"],
        ),
        text_tool(
            "enprot_snapshot",
            "Record the file's chain head hash to <file>.snapshot for later pinning.",
            json!({ "path": { "type": "string" } }),
            &["path"],
        ),
        text_tool(
            "enprot_pin",
            "Verify the file's current chain head matches an expected hash \
             (from enprot_snapshot). Fails on mismatch.",
            json!({
                "path": { "type": "string" },
                "expected": { "type": "string",
                              "description": "expected chain-head hash (64 hex chars)" }
            }),
            &["path", "expected"],
        ),
        text_tool(
            "enprot_cap_check",
            "Check whether an operation on a WORD is allowed by the capability \
             policy (.enprot/policy.toml). Read-only.",
            json!({
                "word": { "type": "string" },
                "op": { "type": "string", "enum": [
                    "encrypt", "decrypt", "store", "fetch", "verify"
                ] }
            }),
            &["word", "op"],
        ),
    ]
}

pub fn dispatch(
    name: &str,
    args: &JsonObject,
    policy: &McpPolicy,
) -> Result<CallToolResult, ErrorData> {
    match name {
        "enprot_inspect" => inspect(args, policy),
        "enprot_encrypt" => encrypt(args, policy),
        "enprot_decrypt" => decrypt(args, policy),
        "enprot_verify" => verify(args, policy),
        "enprot_verify_chain" => verify_chain(args, policy),
        "enprot_snapshot" => snapshot(args, policy),
        "enprot_pin" => pin(args, policy),
        "enprot_cap_check" => cap_show(args, policy),
        other => Err(ErrorData::internal_error(
            format!("unknown tool: {other}"),
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: Value) -> JsonObject {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn catalog_names_are_stable() {
        let names: Vec<String> = catalog().iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names,
            vec![
                "enprot_inspect".to_string(),
                "enprot_encrypt".to_string(),
                "enprot_decrypt".to_string(),
                "enprot_verify".to_string(),
                "enprot_verify_chain".to_string(),
                "enprot_snapshot".to_string(),
                "enprot_pin".to_string(),
                "enprot_cap_check".to_string(),
            ]
        );
    }

    #[test]
    fn every_catalog_tool_dispatches() {
        let policy = McpPolicy::default_read_only();
        for tool in catalog() {
            // Dispatch with empty args: the tool must at least be
            // ROUTED (invalid-params error proves routing works;
            // unknown tool would say "unknown tool").
            let err = dispatch(tool.name.as_ref(), &args(json!({})), &policy).unwrap_err();
            assert!(
                err.to_string().contains("invalid tool arguments"),
                "{} not routed: {err}",
                tool.name
            );
        }
    }

    #[test]
    fn inspect_policy_denied_before_spawn() {
        let policy = McpPolicy::default_read_only();
        let result = dispatch(
            "enprot_inspect",
            &args(json!({ "path": "/etc/passwd" })),
            &policy,
        )
        .unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap().text.to_string();
        assert!(text.contains("policy denied"), "got {text}");
    }

    #[test]
    fn encrypt_requires_write_policy() {
        let policy = McpPolicy::default_read_only();
        let result = dispatch(
            "enprot_encrypt",
            &args(json!({ "path": "doc.ept", "words": ["W"] })),
            &policy,
        )
        .unwrap();
        assert_eq!(result.is_error, Some(true));
    }
}
