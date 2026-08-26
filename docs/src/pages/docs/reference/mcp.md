---
title: "MCP Server (AI Agents)"
layout: ../../../layouts/DocPage.astro
---

<!--
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
-->

# enprot MCP server

`enprot-mcp` exposes enprot to AI agents (Claude Code, Cursor,
Continue, …) over the [Model Context
Protocol](https://modelcontextprotocol.io). Agents get typed tool
calls with structured JSON results instead of shelling out, parsing
text, and hoping nothing goes wrong.

## Tools

| Tool | What it does | Access |
|---|---|---|
| `enprot_inspect` | Structure report: blocks, chain anchors, conflicts | read |
| `enprot_encrypt` | Encrypt WORD segments in place (supports ciphers, escrow `recovery_keys`, store-to-CAS) | write |
| `enprot_decrypt` | Decrypt WORD segments in place (passwords or `key_file`) | write |
| `enprot_verify` | Structural integrity check | read |
| `enprot_verify_chain` | Chain-anchor signature + DAG verification against trust roots | read |
| `enprot_snapshot` | Record the chain head to `<file>.snapshot` | read + write sidecar |
| `enprot_pin` | Verify the chain head matches an expected hash | read |
| `enprot_cap_check` | Ask the capability policy whether an operation on a WORD is allowed | read |

Read-only tools return the CLI's `--format json` output as
`structuredContent`. Failures (including policy denials) return
tool-level `isError` results with the actionable message.

## Policy — what the agent may touch

Every tool invocation is gated by `.enprot/mcp-policy.toml` in the
server's working directory (the agent's project root), evaluated
**before** anything runs:

```toml
allow_read  = ["src/**", "docs/**", "*.ept", "*.pub.pem"]
allow_write = ["secrets.ept"]
deny        = [".env", ".ssh/**", "**/.git/**"]
```

- `deny` always wins.
- With **no policy file**, the server is read-only inside the working
  directory (absolute paths and `..` escapes rejected) and denies
  every write — safe out of the box; add the file to unlock writes.

## Setup

The server locates the `enprot` binary via `$ENPROT_BIN`, then as a
sibling of `enprot-mcp` (release installs ship both), then on `PATH`.

**Claude Code** (`.mcp.json` in the project, or `~/.claude.json`):

```json
{
  "mcpServers": {
    "enprot": { "command": "enprot-mcp" }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "enprot": { "command": "enprot-mcp" }
  }
}
```

**Continue** (`.continue/config.json`):

```json
{
  "mcpServers": {
    "enprot": { "command": "enprot-mcp", "args": [] }
  }
}
```

## Example agent workflow

1. `enprot_inspect { "path": "secrets.ept" }` — see which WORD
   segments exist and their state before editing.
2. `enprot_cap_check { "word": "API_KEY", "op": "encrypt" }` —
   confirm the capability policy allows the action.
3. `enprot_encrypt { "path": "secrets.ept", "words": ["API_KEY"],
   "passwords": { "API_KEY": "…" }, "cipher": "aes-256-siv" }`.
4. `enprot_snapshot { "path": "secrets.ept" }` before committing;
   CI later runs `enprot_pin` with the recorded head hash.

## Notes

- Passwords supplied via `passwords` reach the CLI as `-k` arguments.
  On multi-user machines prefer an account without other local users,
  or wait for env/stdin password plumbing for the MCP path.
- The server is a typed driver over the `enprot` CLI — one
  implementation of the pipeline (the CLI), zero drift.
