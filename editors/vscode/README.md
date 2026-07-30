# enprot — Visual Studio Code extension

Syntax highlighting, code folding, and a plaintext-leak warning for
[EPT (Engyon Protected Text)][ept] directives embedded in source
comments. Bundles commands that call the `enprot` CLI binary.

[ept]: https://github.com/engyon/enprot

## What it does

- **Syntax highlighting** for `.ept` files.
- **Injection grammar** — highlights `BEGIN`/`END`/`ENCRYPTED`/`STORED`/`DATA` keywords inside comments of Python, Rust, Go, shell, TOML, YAML, JSON.
- **Folding** — BEGIN/END blocks fold as a unit.
- **Diagnostics** — warning decoration when a `BEGIN WORD` block contains plaintext (likely a committed secret).
- **Commands** — encrypt / decrypt / store / verify the active file via the enprot binary.

## Install

The extension does NOT bundle the `enprot` binary. Install it separately:

```sh
cargo install --locked --features vendored-rnp --git https://github.com/engyon/enprot
# or
brew install enprot   # once the tap is published
```

Then in VS Code, install this extension from the Marketplace, or
side-load from this directory:

```sh
cd editors/vscode
npm install        # dev deps only
# Press F5 in VS Code to launch an Extension Development Host
```

## Commands

Run from the Command Palette (`⇧⌘P`):

- `enprot: Encrypt file`
- `enprot: Decrypt file`
- `enprot: Store (CAS-sanitize) file`
- `enprot: Verify chain anchors`

Each command prompts for a `WORD=password` pair (interactive, never
written to settings).

## Configuration

| Setting | Default | Description |
|---|---|---|
| `enprot.binaryPath` | `"enprot"` | Path to the enprot binary. Defaults to enprot on `$PATH`. |
| `enprot.warnOnPlaintextBeginBlock` | `true` | Show a warning when a `BEGIN WORD` block contains plaintext. |
| `enprot.defaultCasdir` | `".cas"` | CAS directory used by encrypt/decrypt/store. |

## License

BSD-2-Clause, same as the enprot Rust crate.
