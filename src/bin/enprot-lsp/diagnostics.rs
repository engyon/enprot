//! Plaintext-in-BEGIN-block diagnostics for the LSP server.
//!
//! Same detection logic as the pre-commit hook and the VS Code
//! extension: if a BEGIN WORD block contains body that isn't
//! ENCRYPTED/STORED/DATA, it's flagged as a potential committed-secret.

/// Check a file for plaintext-inside-BEGIN-block violations.
///
/// Returns LSP diagnostic JSON objects (range + severity + message).
pub fn check_plaintext_in_begin(_uri: &str, text: &str) -> Vec<serde_json::Value> {
    let mut diags = Vec::new();
    let mut in_begin: Option<(String, usize)> = None; // (word, start_line)
    let mut body_clean = false;

    for (i, line) in text.lines().enumerate() {
        if let Some(kw) = match_directive(line) {
            match kw.as_str() {
                "BEGIN" => {
                    let word = extract_word(line, &kw).unwrap_or_default();
                    in_begin = Some((word, i));
                    body_clean = false;
                }
                "ENCRYPTED" | "STORED" | "DATA" | "CHAIN" => {
                    body_clean = true;
                }
                "END" => {
                    if let Some((ref w, start)) = in_begin
                        && !body_clean
                    {
                        diags.push(serde_json::json!({
                                "range": {
                                    "start": { "line": start, "character": 0 },
                                    "end": { "line": i, "character": line.len() },
                                },
                                "severity": 2,  // Warning
                                "source": "enprot",
                                "message": format!(
                                    "plaintext inside BEGIN {w} block — run `enprot encrypt` or `enprot store` before committing"
                                ),
                            }));
                    }
                    in_begin = None;
                    body_clean = false;
                }
                _ => {}
            }
        }
    }

    diags
}

/// Check if a line contains an EPT directive keyword. Returns the
/// keyword if found (e.g., "BEGIN", "END", "ENCRYPTED").
fn match_directive(line: &str) -> Option<String> {
    let keywords = [
        "BEGIN",
        "END",
        "ENCRYPTED",
        "STORED",
        "DATA",
        "CHAIN",
        "IMMUTABLE",
        "MUTABLE",
        "MUTED",
        "CONFLICT",
        "INCLUDE",
        "OURS",
        "THEIRS",
    ];
    for kw in &keywords {
        if line.contains(kw) {
            return Some(kw.to_string());
        }
    }
    None
}

/// Extract the WORD from a directive line like `// <( BEGIN SECRET )>`.
fn extract_word(line: &str, keyword: &str) -> Option<String> {
    let after_kw = line.split_once(keyword)?.1.trim();
    after_kw.split_whitespace().next().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_encrypted_file_no_diagnostics() {
        let text = "// <( ENCRYPTED SECRET )>\n// <( DATA abc )>\n// <( END SECRET )>\n";
        let diags = check_plaintext_in_begin("file:///test.ept", text);
        assert!(
            diags.is_empty(),
            "expected no diagnostics for encrypted block"
        );
    }

    #[test]
    fn plaintext_in_begin_produces_warning() {
        let text = "// <( BEGIN SECRET )>\nhunter2\n// <( END SECRET )>\n";
        let diags = check_plaintext_in_begin("file:///test.ept", text);
        assert_eq!(diags.len(), 1, "expected 1 diagnostic, got {}", diags.len());
        let msg = diags[0]
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        assert!(msg.contains("plaintext"), "msg: {msg}");
    }

    #[test]
    fn plain_text_without_directives_no_diagnostics() {
        let text = "just a plain file\nno directives\n";
        let diags = check_plaintext_in_begin("file:///test.ept", text);
        assert!(diags.is_empty());
    }

    #[test]
    fn stored_block_no_diagnostics() {
        let text = "// <( STORED SECRET abc123 )>\nplain text after\n";
        let diags = check_plaintext_in_begin("file:///test.ept", text);
        assert!(
            diags.is_empty(),
            "STORED blocks should not trigger warnings"
        );
    }
}
