// Copyright (c) 2018-2026 [Ribose Inc](https://www.ribose.com).
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source source must retain the above copyright
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

//! Filesystem policy gate (TODO.complete/57): which paths the MCP
//! server may touch, evaluated BEFORE any tool runs.
//!
//! ```toml
//! # .enprot/mcp-policy.toml
//! allow_read  = ["src/**", "docs/**", "*.ept"]
//! allow_write = ["secrets.ept"]
//! deny        = [".env", ".ssh/**"]
//! ```
//!
//! Evaluation order: `deny` first (always wins), then the allow list
//! for the requested access, then the default. With no policy file
//! the server runs **read-only inside the working directory** and
//! denies every write — safe out of the box, explicit to unlock.

use glob::Pattern;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug)]
pub struct McpPolicy {
    allow_read: Vec<Arc<Pattern>>,
    allow_write: Vec<Arc<Pattern>>,
    deny: Vec<Arc<Pattern>>,
    /// Path the policy was loaded from, for diagnostics.
    pub source: Option<PathBuf>,
}

#[derive(Debug)]
pub struct Denied {
    pub path: PathBuf,
    pub access: Access,
    pub reason: String,
}

impl McpPolicy {
    /// Load from `./.enprot/mcp-policy.toml` (relative to the
    /// server's working directory — the agent's project root).
    pub fn discover() -> Self {
        Self::load(Path::new(".enprot/mcp-policy.toml"))
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text).with_source(path),
            Err(_) => Self::default_read_only(),
        }
    }

    pub(crate) fn with_source(mut self, path: &Path) -> Self {
        self.source = Some(path.to_path_buf());
        self
    }

    pub(crate) fn from_toml(text: &str) -> Self {
        #[derive(serde::Deserialize, Default)]
        struct Raw {
            #[serde(default)]
            allow_read: Vec<String>,
            #[serde(default)]
            allow_write: Vec<String>,
            #[serde(default)]
            deny: Vec<String>,
        }
        let raw: Raw = toml::from_str(text).unwrap_or_default();
        let compile = |pats: Vec<String>| {
            pats.into_iter()
                .filter_map(|p| Pattern::new(&p).ok().map(Arc::new))
                .collect::<Vec<_>>()
        };
        McpPolicy {
            allow_read: compile(raw.allow_read),
            allow_write: compile(raw.allow_write),
            deny: compile(raw.deny),
            source: None,
        }
    }

    pub(crate) fn default_read_only() -> Self {
        McpPolicy {
            allow_read: vec![Pattern::new("**").map(Arc::new).expect("valid pattern")],
            allow_write: Vec::new(),
            deny: Vec::new(),
            source: None,
        }
    }

    /// Check one path for one access mode. Deny wins, then the
    /// matching allow list. The no-policy-file default confines reads
    /// to the working directory: absolute paths and `..` escapes are
    /// rejected even though its pattern is `**`. An explicit policy
    /// may allow absolute paths — its patterns say so on purpose.
    pub fn check(&self, path: &Path, access: Access) -> Result<(), Denied> {
        let display = path.display().to_string();
        if self.deny.iter().any(|p| p.matches(&display)) {
            return Err(Denied {
                path: path.to_path_buf(),
                access,
                reason: "path matches a deny pattern in the MCP policy".to_string(),
            });
        }
        let (allowed, label) = match access {
            Access::Read => (&self.allow_read, "read"),
            Access::Write => (&self.allow_write, "write"),
        };
        if allowed.iter().any(|p| p.matches(&display)) {
            let escapes = if self.source.is_none() {
                display.starts_with('/') || display.split('/').any(|c| c == "..")
            } else {
                false
            };
            if !escapes {
                return Ok(());
            }
        }
        Err(Denied {
            path: path.to_path_buf(),
            access,
            reason: format!(
                "path is not allowed for {label} by the MCP policy \
                 (.enprot/mcp-policy.toml)"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> McpPolicy {
        McpPolicy::from_toml(text).with_source(Path::new("test-policy"))
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy("allow_read = [\"**\"]\ndeny = [\".env\"]\n");
        assert!(p.check(Path::new(".env"), Access::Read).is_err());
        assert!(p.check(Path::new("src/main.rs"), Access::Read).is_ok());
    }

    #[test]
    fn write_needs_explicit_allow() {
        let p = policy("allow_read = [\"**\"]\nallow_write = [\"secrets.ept\"]\n");
        assert!(p.check(Path::new("secrets.ept"), Access::Write).is_ok());
        assert!(p.check(Path::new("other.ept"), Access::Write).is_err());
    }

    #[test]
    fn default_is_read_only() {
        let p = McpPolicy::default_read_only();
        assert!(p.check(Path::new("docs/a.ept"), Access::Read).is_ok());
        assert!(p.check(Path::new("anything.ept"), Access::Write).is_err());
    }

    #[test]
    fn default_rejects_absolute_paths_outside_cwd() {
        let p = McpPolicy::default_read_only();
        assert!(p.check(Path::new("/etc/passwd"), Access::Read).is_err());
    }

    #[test]
    fn glob_semantics() {
        let p = policy("allow_read = [\"src/**\", \"*.ept\"]\n");
        assert!(p.check(Path::new("src/a/b.rs"), Access::Read).is_ok());
        assert!(p.check(Path::new("doc.ept"), Access::Read).is_ok());
        assert!(p.check(Path::new("docs/doc.md"), Access::Read).is_err());
    }
}
