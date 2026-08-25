// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
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

//! `enprot-mcp` — expose enprot to AI agents over the Model Context
//! Protocol (TODO.complete/57).
//!
//! Design: the server is a **typed, policy-gated driver over the
//! `enprot` CLI**, not a reimplementation of the pipeline. The CLI is
//! the stable contract (its `--format json` modes give structured
//! output); duplicating the transform pipeline here would violate
//! MECE and drift. The MCP layer adds what agents actually need:
//!
//! - typed input schemas (no shell escaping, no text parsing),
//! - a filesystem policy gate that runs BEFORE any tool executes
//!   (`.enprot/mcp-policy.toml`),
//! - structured results (`structuredContent`) parsed from the CLI's
//!   JSON output where available.
//!
//! Binary location: `$ENPROT_BIN`, else the `enprot` sibling of this
//! executable (release installs ship both in `bin/`), else `enprot`
//! on `PATH`.

mod driver;
mod policy;
mod tools;

use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, ListToolsResult, PaginatedRequestParams,
};
use rmcp::service::{RequestContext, RoleServer, RunningService, serve_server};
use std::sync::Arc;

struct EnprotMcp {
    policy: Arc<policy::McpPolicy>,
}

impl ServerHandler for EnprotMcp {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = request.arguments.unwrap_or_default();
        let result = tools::dispatch(&request.name, &args, &self.policy)?;
        Ok(CallToolResponse::Complete(result))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            result_type: None,
            meta: None,
            next_cursor: None,
            ttl_ms: None,
            cache_scope: None,
            tools: tools::catalog(),
        })
    }

    async fn ping(&self, _context: RequestContext<RoleServer>) -> Result<(), ErrorData> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let policy = policy::McpPolicy::discover();
    if policy.source.is_none() {
        eprintln!(
            "enprot-mcp: no .enprot/mcp-policy.toml found; running read-only \
             (reads restricted to the working directory, writes denied)"
        );
    }
    let handler = EnprotMcp {
        policy: Arc::new(policy),
    };
    let service: RunningService<RoleServer, EnprotMcp> =
        serve_server(handler, rmcp::transport::io::stdio())
            .await
            .expect("failed to start MCP stdio transport");
    service.waiting().await.expect("MCP service errored");
}
