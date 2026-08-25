// E2E tests for the enprot-mcp server (TODO.complete/57): spawn the
// compiled binary, speak MCP JSON-RPC over stdio, exercise the tool
// surface end to end against the real `enprot` CLI.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

struct McpChild {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: AtomicU64,
}

impl McpChild {
    fn spawn(cwd: &std::path::Path, enprot_bin: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enprot-mcp"))
            .current_dir(cwd)
            .env("ENPROT_BIN", enprot_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn enprot-mcp");
        let reader = BufReader::new(child.stdout.take().expect("stdout"));
        let mut me = McpChild {
            child,
            reader,
            next_id: AtomicU64::new(1),
        };
        me.handshake();
        me
    }

    fn send(&mut self, value: &Value) {
        let stdin = self.child.stdin.as_mut().expect("stdin");
        serde_json::to_writer(&mut *stdin, value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("read response");
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = serde_json::from_str(&line).expect("valid JSON-RPC line");
            if msg.get("id").and_then(|i| i.as_u64()) == Some(id) {
                assert!(
                    msg.get("result").is_some(),
                    "JSON-RPC error response: {msg}"
                );
                return msg;
            }
            // notifications and other responses: skip
        }
    }

    fn handshake(&mut self) {
        let resp = self.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "enprot-mcp-test", "version": "0" }
            }),
        );
        assert!(resp.get("result").is_some(), "initialize failed: {resp}");
        self.send(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
    }

    fn tools_list(&mut self) -> Vec<String> {
        let resp = self.request("tools/list", serde_json::json!({}));
        resp["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    fn call_tool(&mut self, name: &str, args: Value) -> Value {
        self.request(
            "tools/call",
            serde_json::json!({ "name": name, "arguments": args }),
        )["result"]
            .clone()
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn enprot_bin() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug/enprot")
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn tools_list_exposes_the_enprot_surface() {
    let root = workspace_root();
    let mut mcp = McpChild::spawn(&root, &enprot_bin());
    let tools = mcp.tools_list();
    for expected in [
        "enprot_inspect",
        "enprot_encrypt",
        "enprot_decrypt",
        "enprot_verify",
        "enprot_verify_chain",
        "enprot_snapshot",
        "enprot_pin",
        "enprot_cap_check",
    ] {
        assert!(tools.iter().any(|t| t == expected), "missing {expected}");
    }
}

#[test]
fn inspect_returns_structured_content() {
    let root = workspace_root();
    let mut mcp = McpChild::spawn(&root, &enprot_bin());
    let result = mcp.call_tool(
        "enprot_inspect",
        serde_json::json!({ "path": "sample/test.ept" }),
    );
    assert!(
        result.get("structuredContent").is_some()
            || !result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
        "inspect returned nothing: {result}"
    );
    assert_ne!(result.get("isError"), Some(&serde_json::json!(true)));
}

#[test]
fn write_tools_are_denied_without_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("doc.ept"),
        "// <( BEGIN W )>\nx\n// <( END W )>\n",
    )
    .unwrap();
    let mut mcp = McpChild::spawn(dir.path(), &enprot_bin());
    let result = mcp.call_tool(
        "enprot_encrypt",
        serde_json::json!({ "path": "doc.ept", "words": ["W"], "passwords": { "W": "pw" } }),
    );
    assert_eq!(result.get("isError"), Some(&serde_json::json!(true)));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("MCP policy"), "got {text}");
    // The file must be untouched.
    let content = std::fs::read_to_string(dir.path().join("doc.ept")).unwrap();
    assert!(content.contains("BEGIN W"));
}

#[test]
fn read_outside_cwd_is_denied_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let mut mcp = McpChild::spawn(dir.path(), &enprot_bin());
    let result = mcp.call_tool(
        "enprot_inspect",
        serde_json::json!({ "path": "/etc/passwd" }),
    );
    assert_eq!(result.get("isError"), Some(&serde_json::json!(true)));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("policy denied"), "got {text}");
}

#[test]
fn encrypt_roundtrip_with_policy() {
    let dir = tempfile::tempdir().unwrap();
    let dot = dir.path().join(".enprot");
    std::fs::create_dir(&dot).unwrap();
    std::fs::write(
        dot.join("mcp-policy.toml"),
        "allow_read = [\"**\"]\nallow_write = [\"doc.ept\"]\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("doc.ept"),
        "// <( BEGIN W )>\nhello\n// <( END W )>\n",
    )
    .unwrap();

    let mut mcp = McpChild::spawn(dir.path(), &enprot_bin());

    let enc = mcp.call_tool(
        "enprot_encrypt",
        serde_json::json!({
            "path": "doc.ept",
            "words": ["W"],
            "passwords": { "W": "pw" },
            "cipher": "aes-256-siv"
        }),
    );
    assert_ne!(
        enc.get("isError"),
        Some(&serde_json::json!(true)),
        "encrypt: {enc}"
    );
    let content = std::fs::read_to_string(dir.path().join("doc.ept")).unwrap();
    assert!(content.contains("ENCRYPTED"), "not encrypted: {content}");

    let dec = mcp.call_tool(
        "enprot_decrypt",
        serde_json::json!({
            "path": "doc.ept",
            "words": ["W"],
            "passwords": { "W": "pw" }
        }),
    );
    assert_ne!(
        dec.get("isError"),
        Some(&serde_json::json!(true)),
        "decrypt: {dec}"
    );
    let content = std::fs::read_to_string(dir.path().join("doc.ept")).unwrap();
    assert!(content.contains("hello"), "not decrypted: {content}");
}
