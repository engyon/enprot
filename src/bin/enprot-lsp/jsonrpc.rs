//! LSP JSON-RPC framing over stdio.
//!
//! LSP uses Content-Length headers + JSON body, per the
//! [Language Server Protocol Specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/).

use std::io::{BufRead, Write};

/// Read one LSP message from `reader`. Returns `None` at EOF.
pub fn read_message<R: BufRead>(reader: &mut R) -> Option<serde_json::Value> {
    let mut content_length: Option<usize> = None;

    // Read headers until empty line.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None; // EOF
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break; // End of headers
        }
        if let Some(len) = trimmed.strip_prefix("Content-Length: ") {
            content_length = len.parse().ok();
        }
        // Ignore other headers (Content-Type, etc.)
    }

    let len = content_length?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// Write one LSP message to `writer`.
pub fn write_message<W: Write>(writer: &mut W, msg: &serde_json::Value) {
    let body = serde_json::to_string(msg).unwrap_or_default();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    let _ = writer.write_all(header.as_bytes());
    let _ = writer.write_all(body.as_bytes());
    let _ = writer.flush();
}

/// Build a successful JSON-RPC response.
pub fn success_response(
    id: Option<&serde_json::Value>,
    result: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Build an error JSON-RPC response.
pub fn error_response(
    id: Option<&serde_json::Value>,
    code: i64,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}
