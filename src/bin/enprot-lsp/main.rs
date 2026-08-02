//! Minimal LSP server for EPT files (TODO.complete/13).
//!
//! Status: **scaffold** — speaks the LSP JSON-RPC protocol over stdio
//! and provides one real feature: plaintext-in-BEGIN-block diagnostics
//! (same detection logic as the VS Code extension's regex-based check
//! and the pre-commit hook).
//!
//! Not yet implemented:
//! - Hover (WORD documentation)
//! - Document symbols
//! - Go-to-definition (WORD → CAS file)
//! - Code actions (encrypt/store)
//! - Formatting
//!
//! These features require tower-lsp or a full LSP framework, which
//! pulls in tokio (~2 MB). This scaffold hand-rolls the JSON-RPC
//! framing to stay dependency-free.
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
