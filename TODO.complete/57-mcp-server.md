# 57 — MCP server for AI agent integration

**Priority**: P3
**Status**: specified

## Problem

AI agents (Claude Code, Cursor, Continue, etc.) increasingly do
security-sensitive work: editing config files, managing secrets,
auditing supply chains. These agents need:

- A safe way to encrypt/decrypt secrets in their working files.
- A way to verify chain anchors without manually running CLI commands.
- A way to query capability policy before taking an action.

Today, an AI agent must shell out to `enprot` via the CLI, parse
text output, and hope nothing goes wrong. That's error-prone and
limits the agent's ability to integrate enprot into its workflows.

The **Model Context Protocol (MCP)** is the emerging standard for
exposing tools to AI agents. An enprot MCP server would let any
MCP-aware agent invoke enprot operations as typed tool calls, with
structured input/output, without shell escaping or text parsing.

## Goals

- A `enprot-mcp` binary that implements the MCP server protocol.
- Tools exposed:
  - `enprot_encrypt` — encrypt WORD segments in a file.
  - `enprot_decrypt` — decrypt WORD segments.
  - `enprot_inspect` — show structure + chain anchors of a file.
  - `enprot_verify` — verify structural integrity.
  - `enprot_verify_chain` — verify chain anchor signatures.
  - `enprot_snapshot` / `enprot_pin` — chain-head pinning.
  - `enprot_cap_show` — show held capabilities.
- Each tool has a typed JSON schema for input + output.
- Configurable policy: which paths the server may read/write.
- Documented setup for Claude Code, Cursor, Continue.

## Goals (non-goals)

- An AI that writes EPT markup autonomously. The MCP server exposes
  tools; the agent decides what to call.
- A natural-language interface to enprot. MCP tools are typed;
  agents handle the NLP layer.
- Training data collection. The MCP server doesn't log or collect.

## Design

### MCP protocol overview

MCP (https://modelcontextprotocol.io) is a JSON-RPC-based protocol
where a "server" exposes "tools" that a "client" (the AI agent)
can call. Servers can be local (stdio) or remote (HTTP/SSE).

For enprot, a local stdio server is the natural choice — agents
run enprot-mcp as a subprocess and communicate over stdin/stdout.

### Tool shape

Each tool is a JSON-RPC method with a typed schema:

```json
{
  "name": "enprot_inspect",
  "description": "Inspect the structure of an EPT file. Returns blocks, chain anchors, conflicts, and held capabilities.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": { "type": "string", "description": "Path to the .ept file" },
      "format": { "type": "string", "enum": ["text", "json"], "default": "json" }
    },
    "required": ["path"]
  }
}
```

Response:

```json
{
  "blocks": [
    { "kind": "encrypted", "word": "SECRET", "cipher": "aes-256-siv" },
    { "kind": "plain" }
  ],
  "chain_anchors": [
    { "id": "abc123...", "signer": "ed25519:def456..." }
  ],
  "conflict_count": 0,
  "capabilities": ["encrypt", "decrypt", "store", "fetch"]
}
```

### Server implementation

```rust
// enprot-mcp/src/main.rs (new binary in the workspace)

use mcp_server::{Server, Tool};

fn main() -> Result<()> {
    let server = Server::new(stdio())
        .tool(InspectTool)
        .tool(EncryptTool)
        .tool(DecryptTool)
        .tool(VerifyChainTool)
        // ...
        .serve();
    Ok(())
}

struct InspectTool;

impl Tool for InspectTool {
    fn name(&self) -> &str { "enprot_inspect" }
    fn description(&self) -> &str { /* ... */ }
    fn input_schema(&self) -> serde_json::Value { /* ... */ }

    fn invoke(&self, input: serde_json::Value) -> Result<serde_json::Value> {
        let path = input["path"].as_str().unwrap();
        let tree = enprot::etree::parse(BufReader::new(File::open(path)?), &mut paops)?;
        // ... build the response JSON ...
        Ok(response)
    }
}
```

### Policy enforcement

The MCP server reads a `.enprot/mcp-policy.toml` that restricts
which paths the server may touch:

```toml
# .enprot/mcp-policy.toml
allow_read = ["src/**", "docs/**", "*.ept"]
allow_write = ["secrets.ept", ".enprot/anchors/"]
deny = [".env", ".ssh/**", "~/.aws/**"]
default = "deny"
```

A tool invocation that violates the policy returns a typed error
before any enprot operation runs.

### Agent setup examples

**Claude Code** (`~/.config/claude-code/skills/enprot.json`):

```json
{
  "name": "enprot",
  "command": ["enprot-mcp", "serve"],
  "tools": ["enprot_inspect", "enprot_encrypt", "enprot_decrypt"]
}
```

**Cursor** (`.cursor/rules/enprot.md`):

```markdown
Use the enprot MCP tools to inspect, encrypt, and decrypt EPT files.
Before editing `secrets.ept`, call `enprot_inspect` to understand its
structure.
```

**Continue** (`.continue/config.json`):

```json
{
  "mcpServers": {
    "enprot": {
      "command": "enprot-mcp",
      "args": ["serve"]
    }
  }
}
```

## Implementation plan

1. Add `enprot-mcp/` workspace member.
2. Add `mcp-server` + `mcp-types` deps.
3. Implement the 7 tools (`inspect`, `encrypt`, `decrypt`, `verify`,
   `verify_chain`, `snapshot`, `cap_show`).
4. Add policy enforcement via `.enprot/mcp-policy.toml`.
5. Document setup for Claude Code, Cursor, Continue.
6. Add an example agent workflow in `docs/mcp-example.md`.
7. Test against at least one real MCP client end-to-end.

## Test plan

- [ ] Server starts and responds to `tools/list`.
- [ ] Each tool round-trips: invoke → result.
- [ ] Policy enforcement rejects a tool call on a denied path.
- [ ] Claude Code / Cursor / Continue can connect and call tools.
- [ ] Documentation walks through a working end-to-end example.

## Out of scope

- A custom MCP client (agents are the clients; enprot is the server).
- Multi-tenant server (each agent gets its own server process).
- Logging of tool invocations for audit (covered by TODO #38 metrics).
- Tool output streaming for large files (defer until a use case appears).
