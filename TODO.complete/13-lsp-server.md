# 13 — LSP server

**Priority**: P2
**Status**: specified

## Problem

The VS Code extension ships a regex-based diagnostic for plaintext-in-BEGIN. That's the floor. A real editor experience needs: hover docs, go-to-WORD-definition, CAS-pointer follow, rename WORD, code actions ("encrypt this block").

## Goals

- `enprot-lsp` binary speaking LSP over stdio.
- Features: diagnostics, hover, document symbols, definition (WORD → CAS file), code actions (encrypt/store), document formatting.
- Bundled with the VS Code extension; callable from Neovim, Helix, Emacs.

## Design

Use `tower-lsp` crate. Server runs as a sidecar process; the VS Code extension spawns it.

```rust
#[tower_lsp::async_trait]
impl LanguageServer for EptLsp {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::INCREMENTAL)),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                ..Default::default()
            },
            ..Default::default()
        })
    }
    // …
}
```

## Implementation plan

1. New binary `src/bin/enprot-lsp.rs`.
2. Reuse the streaming parser from [05-streaming-io].
3. Document symbols: one per BEGIN/END block.
4. Hover: WORD docs from local `enprot` glossary + CHAIN provenance if present.
5. Code actions: "Encrypt this block", "Store to CAS", "Verify signatures".
6. VS Code extension gains `enprot.lsp.enabled` setting; spawns the LSP binary.

## Test plan

- [ ] LSP conformance suite (`lsp-test`) passes.
- [ ] VS Code extension integration test: hover shows WORD docs.

## Out of scope

- Visual markers for ENCRYPTED/DATA ciphertext ranges (semantic tokens — future).
- Multi-file workspace awareness (stay single-file for v1).
