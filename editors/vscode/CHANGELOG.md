# enprot VS Code extension — change log

## 0.1.0

- Initial release.
- Syntax highlighting for `.ept` files (standalone grammar).
- Injection grammar: highlights EPT directives in Python, Rust, Go,
  shell, TOML, YAML, JSON comments.
- Folding markers for BEGIN/END blocks.
- Diagnostic: warns when a BEGIN WORD block contains plaintext.
- Commands: `enprot.encryptFile`, `enprot.decryptFile`,
  `enprot.storeFile`, `enprot.verifyFile`. Each calls the enprot
  binary on the active document and prompts for `WORD=password`.
