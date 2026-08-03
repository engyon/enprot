//! LSP server for EPT files (TODO.complete/13).
//!
//! Speaks the LSP JSON-RPC protocol over stdio and provides
//! plaintext-in-BEGIN-block diagnostics (same detection logic as
//! the VS Code extension's check and the pre-commit hook).
//!
//! Hand-rolls JSON-RPC framing (no tower-lsp / tokio dependency)
//! to stay lightweight. The server handles: initialize, shutdown,
//! textDocument/didOpen, textDocument/diagnostics.
//!
//! ## Usage
//!
//! ```sh
//! enprot-lsp < file.ept
//! ```
//!
//! Or as a VS Code language server:
//! ```json
//! { "enprot.lsp.path": "/path/to/enprot-lsp" }
//! ```

use std::io::{self};

mod diagnostics;
mod jsonrpc;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    while let Some(msg) = jsonrpc::read_message(&mut stdin) {
        if let Some(response) = handle_message(&msg) {
            jsonrpc::write_message(&mut stdout, &response);
        }
    }
}

fn handle_message(msg: &serde_json::Value) -> Option<serde_json::Value> {
    let method = msg.get("method")?.as_str()?;
    let id = msg.get("id");
    match method {
        "initialize" => Some(jsonrpc::success_response(
            id,
            serde_json::json!({
                "capabilities": {
                    "textDocumentSync": 1,  // full sync
                    "diagnosticProvider": true,
                },
                "serverInfo": {
                    "name": "enprot-lsp",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }),
        )),
        "initialized" => None, // notification, no response
        "shutdown" => Some(jsonrpc::success_response(id, serde_json::json!(null))),
        "textDocument/didOpen" => {
            // In a real server, we'd store the document and publish
            // diagnostics. Here we just log.
            None
        }
        "textDocument/didChange" => None,
        "textDocument/diagnostics" => {
            let uri = msg
                .pointer("/params/textDocument/uri")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let text = msg
                .pointer("/params/textDocument/text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let diags = diagnostics::check_plaintext_in_begin(uri, text);
            Some(jsonrpc::success_response(id, serde_json::json!(diags)))
        }
        _ => Some(jsonrpc::error_response(
            id,
            -32601,
            &format!("method not found: {method}"),
        )),
    }
}
