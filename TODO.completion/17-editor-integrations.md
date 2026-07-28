# 17 — Editor integrations (VS Code, JetBrains, Vim, Emacs)

**Priority**: P1
**Status**: specified (multi-week per editor; design shared)

## Problem

enprot's value is "edit encrypted segments inside source files". The
editor story is the daily-use loop. Today users have to:

- Edit the file
- Drop to terminal: `enprot encrypt -w Foo -k Foo=pw file.ept`
- Reload file in editor
- Edit again
- Drop to terminal: `enprot decrypt -w Foo file.ept`
- ...

Painful. No editor integration exists.

## Common design

All editor integrations share a single LSP-style server:

```
editor plugin  ──┐
                ├─→ enprot-lsp  ──→ enprot library (no fork)
editor plugin  ──┘
```

The LSP server exposes:
- `textDocument/didSave` → run `enprot verify` on the saved file
- `textDocument/codeAction` → "Encrypt WORD", "Decrypt WORD",
  "Verify chain", "Sign anchor"
- `textDocument/hover` → show extfield metadata on EPT directives
- `textDocument/semanticTokens` → highlight WORD segments by type
  (encrypted, stored, signed, conflict)
- `workspace/executeCommand` → run transforms

### Per-editor packaging

| Editor | Plugin form | Distribution |
|---|---|---|
| VS Code | `vscode-enprot` extension | Marketplace |
| JetBrains | IntelliJ plugin | Plugins repository |
| Vim/Neovim | `nvim-enprot` Lua plugin | GitHub release |
| Emacs | `enprot-mode` elisp | MELPA |

All call the same LSP binary; differ only in UX (status bar, command
palette, keybindings).

## Phase 1: VS Code extension

Minimum viable:
- Syntax highlighting for EPT directives
- "Encrypt" / "Decrypt" commands via `enprot` CLI subprocess
- Diagnostic markers for CONFLICT blocks (red squiggles)
- Hover tooltip showing ENCRYPTED block metadata

The extension itself is TypeScript + calls `enprot` binary. Doesn't
need the LSP server for Phase 1.

## Phase 2: LSP server

When the extension needs live feedback (decrypt-on-hover, real-time
validation), build `enprot-lsp`. Same Rust codebase, new `[[bin]]`:

```toml
[[bin]]
name = "enprot-lsp"
path = "src/bin/lsp.rs"
required-features = ["lsp"]
```

Feature-gated because tower-lsp is a heavy dep.

## Phase 3: Other editors

JetBrains, Vim, Emacs get LSP clients (configuration only). The
LSP server is the same.

## Acceptance criteria

- [ ] VS Code extension: highlighting + commands
- [ ] Extension published to VS Code Marketplace
- [ ] LSP server design doc
- [ ] LSP server `enprot-lsp` binary
- [ ] Vim/Emacs configs published

## What this is NOT

- A web UI. enprot is a CLI + editor story.
- A standalone GUI. The editor IS the UI.

## Cross-references

- [[01-strategic-vision]] — editor integration is the daily-use unlock
- [[03-readme-positioning]] — screenshots in README
