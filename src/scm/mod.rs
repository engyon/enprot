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

//! Supply-chain manifest (TODO.roadmap/52).
//!
//! The SCM format extends a provenance manifest (TODO.roadmap/51)
//! with dependency entries parsed from `Cargo.toml` / `package.json` /
//! `pyproject.toml`. A vendor signs the manifest with their private
//! key; customers verify with the vendor's pubkey and a capability
//! policy that pins trust roots and forbids specific dependencies.
//!
//! The CLI surface is `enprot scm <subcommand>`:
//!
//! - `scm init` — create an empty manifest
//! - `scm add PATH` — append files or a directory tree
//! - `scm deps MANIFEST_FILE` — parse dependencies and append entries
//! - `scm attest --signer KEY` — sign the manifest (delegates to provenance::attest)
//! - `scm verify --policy-file POLICY MANIFEST` — wrapper around verify-chain + capability policy
//! - `scm diff OLD NEW` — structural diff between two manifests
//!
//! Currently supported dependency formats: Cargo.toml. npm and pip
//! parsers are stubbed and return `Err` until their respective
//! ecosystems ship enough sample input to validate against.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{Error, Result};
use crate::etree::{self, ParseOps, TextNode};
use crate::provenance;

/// Initialize a new (empty) manifest at `path`. The header comment
/// records the absolute path so later diff operations can reference
/// it. Refuses to overwrite an existing file — callers pass `--force`
/// at the CLI layer if they want that.
pub fn init_manifest(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(Error::msg(format!(
            "{} already exists; remove it or pass a different path",
            path.display()
        )));
    }
    std::fs::write(
        path,
        "# enprot supply-chain manifest\n\
         # add files with `enprot scm add PATH`\n\
         # add dependencies with `enprot scm deps Cargo.toml`\n\
         # sign with `enprot scm attest --signer vendor.pem`\n",
    )?;
    Ok(())
}

/// Append every regular file under `path` (file or directory) to the
/// manifest at `manifest_path`. Re-uses [`provenance::build_manifest`]
/// for the actual file-walking so the format stays identical between
/// the standalone manifest command and `scm add`.
pub fn add_to_manifest(manifest_path: &Path, path: &Path, casdir: &Path) -> Result<usize> {
    let existing = std::fs::read_to_string(manifest_path).unwrap_or_default();
    let policy =
        Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.io.casdir = casdir.to_path_buf();
    paops.runtime.fname = manifest_path.display().to_string();

    let mut tree = if existing.trim().is_empty() {
        Vec::new()
    } else {
        etree::parse(std::io::Cursor::new(existing.into_bytes()), &mut paops)?
    };

    let added_tree = if path.is_dir() {
        provenance::build_manifest(path, casdir)?
    } else if path.is_file() {
        let bytes = std::fs::read(path)?;
        let hash = crate::cas::save(bytes, &mut paops)?;
        vec![
            TextNode::Plain(format!("# path: {}", path.display())),
            TextNode::Include { hash },
        ]
    } else {
        return Err(Error::msg(format!(
            "{} is neither a file nor a directory",
            path.display()
        )));
    };

    let added = added_tree
        .iter()
        .filter(|n| matches!(n, TextNode::Include { .. }))
        .count();
    tree.extend(added_tree);

    let f = std::fs::File::create(manifest_path)?;
    let mut w = std::io::BufWriter::new(f);
    etree::tree_write(&mut w, &tree, &mut paops)?;
    Ok(added)
}

/// Parse `cargo_toml_path`'s dependency tables and append one
/// entry per dependency. Covers `[dependencies]`,
/// `[dev-dependencies]`, `[build-dependencies]`,
/// `[target.<cfg>.{dependencies,dev-dependencies,build-dependencies}]`,
/// and `[workspace.dependencies]`. Each entry's source table is
/// recorded in the annotation comment so downstream policy can
/// distinguish test-only deps from runtime deps.
///
/// Workspace-inherited entries (`{ workspace = true }`) emit
/// `=workspace` as the version placeholder. The vendor should
/// re-run `scm deps` against the workspace root Cargo.toml to
/// capture resolved versions.
pub fn add_cargo_deps(
    manifest_path: &Path,
    cargo_toml_path: &Path,
    casdir: &Path,
) -> Result<usize> {
    let raw = std::fs::read_to_string(cargo_toml_path)?;
    let deps = collect_cargo_deps(&raw)?;

    let existing = std::fs::read_to_string(manifest_path).unwrap_or_default();
    let policy =
        Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
    let mut paops = ParseOps::new(policy)?;
    paops.io.casdir = casdir.to_path_buf();
    paops.runtime.fname = manifest_path.display().to_string();

    let mut tree = if existing.trim().is_empty() {
        Vec::new()
    } else {
        etree::parse(std::io::Cursor::new(existing.into_bytes()), &mut paops)?
    };

    let mut added = 0;
    for dep in &deps {
        let bytes = dep.cas_content();
        let hash = crate::cas::save(bytes, &mut paops)?;
        tree.push(TextNode::Plain(format!("# dep: {}", dep.annotation())));
        tree.push(TextNode::Include { hash });
        added += 1;
    }

    let f = std::fs::File::create(manifest_path)?;
    let mut w = std::io::BufWriter::new(f);
    etree::tree_write(&mut w, &tree, &mut paops)?;
    Ok(added)
}

/// A single dependency entry. `source` identifies which Cargo table
/// the entry came from; consumers treat all sources as equally
/// significant for trust purposes but may filter on source for
/// license-policy or attack-surface analysis.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Dep {
    pub source: String,
    pub name: String,
    pub version: String,
}

impl Dep {
    /// Render the manifest annotation. Format: `name=version` for
    /// the default source; `name=version (source)` otherwise. The
    /// CAS content is always `name=version` (no source tag) so
    /// cross-source deduplication works correctly.
    fn annotation(&self) -> String {
        if self.source == "deps" {
            format!("{}={}", self.name, self.version)
        } else {
            format!("{}={} ({})", self.name, self.version, self.source)
        }
    }

    /// CAS content for this entry. Stable across sources so an entry
    /// appearing in both `[dependencies]` and `[dev-dependencies]`
    /// with the same version deduplicates to one CAS blob.
    fn cas_content(&self) -> Vec<u8> {
        format!("{}={}", self.name, self.version).into_bytes()
    }
}

/// Walk every dependency-bearing table in a Cargo manifest.
/// Recognised sources (in stable emission order):
///
/// - `deps` — top-level `[dependencies]`
/// - `dev-deps` — `[dev-dependencies]`
/// - `build-deps` — `[build-dependencies]`
/// - `target <cfg>` — `[target.'<cfg>'.dependencies]` (and dev/build)
/// - `workspace` — `[workspace.dependencies]` (resolved version, not
///   the `workspace = true` inheritance marker)
///
/// Workspace-inherited entries (`{ workspace = true }`) emit
/// `=workspace` as the version; the vendor should re-run scm deps
/// against the workspace root Cargo.toml to capture resolved
/// versions.
fn collect_cargo_deps(cargo_toml: &str) -> Result<Vec<Dep>> {
    let parsed: toml::Value =
        toml::from_str(cargo_toml).map_err(|e| Error::msg(format!("Cargo.toml parse: {e}")))?;
    let mut out = Vec::new();
    collect_from_table(&parsed, "dependencies", "deps", &mut out);
    collect_from_table(&parsed, "dev-dependencies", "dev-deps", &mut out);
    collect_from_table(&parsed, "build-dependencies", "build-deps", &mut out);
    collect_from_table(&parsed, "workspace.dependencies", "workspace", &mut out);
    collect_target_deps(&parsed, &mut out);
    // Stable emission: sort by (source, name) so identical input
    // produces byte-identical manifests across runs.
    out.sort();
    Ok(out)
}

fn collect_from_table(root: &toml::Value, path: &str, source: &str, out: &mut Vec<Dep>) {
    let table = walk_path(root, path).and_then(|v| v.as_table());
    let Some(table) = table else {
        return;
    };
    for (name, val) in table {
        if let Some(dep) = dep_from_value(name, val, source) {
            out.push(dep);
        }
    }
}

fn collect_target_deps(root: &toml::Value, out: &mut Vec<Dep>) {
    let Some(targets) = root.get("target").and_then(|v| v.as_table()) else {
        return;
    };
    for (cfg, inner) in targets {
        let inner = match inner.as_table() {
            Some(t) => t,
            None => continue,
        };
        for (table_name, source) in [
            ("dependencies", "deps"),
            ("dev-dependencies", "dev-deps"),
            ("build-dependencies", "build-deps"),
        ] {
            let Some(t) = inner.get(table_name).and_then(|v| v.as_table()) else {
                continue;
            };
            for (name, val) in t {
                if let Some(mut dep) = dep_from_value(name, val, source) {
                    dep.source = format!("target {cfg}:{source}");
                    out.push(dep);
                }
            }
        }
    }
}

fn dep_from_value(name: &str, val: &toml::Value, source: &str) -> Option<Dep> {
    match val {
        toml::Value::String(s) => Some(Dep {
            source: source.to_string(),
            name: name.to_string(),
            version: s.clone(),
        }),
        toml::Value::Table(t) => {
            if t.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
                Some(Dep {
                    source: source.to_string(),
                    name: name.to_string(),
                    version: "workspace".to_string(),
                })
            } else {
                t.get("version").and_then(|v| v.as_str()).map(|v| Dep {
                    source: source.to_string(),
                    name: name.to_string(),
                    version: v.to_string(),
                })
            }
        }
        _ => None,
    }
}

fn walk_path<'a>(root: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Structural diff between two manifests. Reports added / removed /
/// changed entries by their `# path:` / `# dep:` annotation. Returns
/// a human-readable summary string.
pub fn diff_manifests(old_path: &Path, new_path: &Path) -> Result<String> {
    let old = parse_index(old_path)?;
    let new = parse_index(new_path)?;
    let mut out = String::new();
    for (key, hash) in &new {
        match old.get(key) {
            None => out.push_str(&format!("+ {key} ({hash})\n")),
            Some(old_hash) if old_hash != hash => {
                out.push_str(&format!("~ {key}: {old_hash} → {hash}\n"))
            }
            _ => {}
        }
    }
    for key in old.keys() {
        if !new.contains_key(key) {
            out.push_str(&format!("- {key}\n"));
        }
    }
    if out.is_empty() {
        out.push_str("(no changes)\n");
    }
    Ok(out)
}

/// Parse a manifest into a (label → hash) map. Labels come from the
/// `# path:` and `# dep:` comments preceding each INCLUDE.
fn parse_index(path: &Path) -> Result<BTreeMap<String, String>> {
    let raw = std::fs::read_to_string(path)?;
    let mut index: BTreeMap<String, String> = BTreeMap::new();
    let mut pending_label: Option<String> = None;
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("# path: ") {
            pending_label = Some(format!("path:{rest}"));
        } else if let Some(rest) = trimmed.strip_prefix("# dep: ") {
            pending_label = Some(format!("dep:{rest}"));
        } else if trimmed.starts_with("// <( INCLUDE ") {
            // Line shape: `// <( INCLUDE <hash> )>`. Token[3] is
            // the hash; the closing `)>` is token[4].
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() >= 4 {
                let hash = tokens[3].trim_end_matches(")>");
                if let Some(label) = pending_label.take() {
                    index.insert(label, hash.to_string());
                }
            }
        }
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(p: &Path, contents: &str) {
        fs::write(p, contents).unwrap();
    }

    #[test]
    fn init_creates_empty_manifest_with_header() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("manifest.ept");
        init_manifest(&p).unwrap();
        let body = fs::read_to_string(&p).unwrap();
        assert!(body.contains("supply-chain manifest"));
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("manifest.ept");
        write(&p, "existing");
        assert!(init_manifest(&p).is_err());
    }

    #[test]
    fn add_appends_files_to_existing_manifest() {
        let dir = tempdir().unwrap();
        let cas = tempdir().unwrap();
        let manifest = dir.path().join("m.ept");
        init_manifest(&manifest).unwrap();
        let src = dir.path().join("a.txt");
        write(&src, "alpha");

        let n = add_to_manifest(&manifest, &src, cas.path()).unwrap();
        assert_eq!(n, 1);
        let body = fs::read_to_string(&manifest).unwrap();
        assert!(body.contains("INCLUDE"));
        assert!(body.contains("# path: "));
    }

    #[test]
    fn cargo_deps_parser_handles_simple_and_table_forms() {
        let toml = r#"
[package]
name = "demo"

[dependencies]
serde = "1.0"
toml = { version = "0.8", features = ["preserve_order"] }
hex = "0.4"
"#;
        let deps = collect_cargo_deps(toml).unwrap();
        let map: BTreeMap<String, Dep> = deps.into_iter().map(|d| (d.name.clone(), d)).collect();
        assert_eq!(map.get("serde").map(|d| d.version.as_str()), Some("1.0"));
        assert_eq!(map.get("toml").map(|d| d.version.as_str()), Some("0.8"));
        assert_eq!(map.get("hex").map(|d| d.version.as_str()), Some("0.4"));
        // Default source tag.
        assert_eq!(map.get("serde").map(|d| d.source.as_str()), Some("deps"));
    }

    #[test]
    fn cargo_deps_parser_covers_dev_build_target_tables() {
        let toml = r#"
[dependencies]
serde = "1.0"
[dev-dependencies]
tempfile = "3"
[build-dependencies]
cc = "1.0"
[target.'cfg(unix)'.dependencies]
openssl = "0.10"
"#;
        let deps = collect_cargo_deps(toml).unwrap();
        let by_name: BTreeMap<String, Dep> =
            deps.into_iter().map(|d| (d.name.clone(), d)).collect();
        assert_eq!(by_name["serde"].source, "deps");
        assert_eq!(by_name["tempfile"].source, "dev-deps");
        assert_eq!(by_name["cc"].source, "build-deps");
        assert_eq!(by_name["openssl"].source, "target cfg(unix):deps");
    }

    #[test]
    fn cargo_deps_workspace_inherited_emits_placeholder() {
        let toml = r#"
[dependencies]
serde = { workspace = true }
[workspace.dependencies]
serde = "1.0"
"#;
        let deps = collect_cargo_deps(toml).unwrap();
        // Two entries: the inherited one with `=workspace`, and the
        // workspace-root definition with the resolved version.
        let serde_entries: Vec<&Dep> = deps.iter().filter(|d| d.name == "serde").collect();
        assert_eq!(serde_entries.len(), 2);
        assert!(serde_entries.iter().any(|d| d.version == "workspace"));
        assert!(serde_entries.iter().any(|d| d.version == "1.0"));
    }

    #[test]
    fn add_cargo_deps_appends_one_entry_per_dependency() {
        let dir = tempdir().unwrap();
        let cas = tempdir().unwrap();
        let manifest = dir.path().join("m.ept");
        init_manifest(&manifest).unwrap();
        let cargo = dir.path().join("Cargo.toml");
        write(
            &cargo,
            r#"
[package]
name = "demo"
[dependencies]
serde = "1.0"
hex = "0.4"
"#,
        );

        let n = add_cargo_deps(&manifest, &cargo, cas.path()).unwrap();
        assert_eq!(n, 2);
        let body = fs::read_to_string(&manifest).unwrap();
        assert!(body.contains("# dep: serde=1.0"));
        assert!(body.contains("# dep: hex=0.4"));
    }

    #[test]
    fn diff_reports_added_removed_changed_entries() {
        let dir = tempdir().unwrap();
        let cas = tempdir().unwrap();
        let old = dir.path().join("old.ept");
        let new = dir.path().join("new.ept");

        let old_proj = dir.path().join("old_proj");
        let new_proj = dir.path().join("new_proj");
        fs::create_dir_all(&old_proj).unwrap();
        fs::create_dir_all(&new_proj).unwrap();
        write(&old_proj.join("a.txt"), "alpha");
        write(&old_proj.join("b.txt"), "beta");
        write(&new_proj.join("a.txt"), "alpha-modified");
        write(&new_proj.join("c.txt"), "gamma");

        let old_tree = provenance::build_manifest(&old_proj, cas.path()).unwrap();
        let new_tree = provenance::build_manifest(&new_proj, cas.path()).unwrap();

        let policy =
            Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
        let mut paops = ParseOps::new(policy).unwrap();
        paops.io.casdir = cas.path().to_path_buf();
        let mut w = std::io::BufWriter::new(std::fs::File::create(&old).unwrap());
        etree::tree_write(&mut w, &old_tree, &mut paops).unwrap();
        drop(w);
        let mut w = std::io::BufWriter::new(std::fs::File::create(&new).unwrap());
        etree::tree_write(&mut w, &new_tree, &mut paops).unwrap();
        drop(w);

        // Sanity-check the manifests we wrote.
        let old_body = fs::read_to_string(&old).unwrap();
        let new_body = fs::read_to_string(&new).unwrap();
        assert!(old_body.contains("# path: a.txt"), "old = {old_body}");
        assert!(new_body.contains("# path: c.txt"), "new = {new_body}");

        let d = diff_manifests(&old, &new).unwrap();
        assert!(d.contains("+ path:"), "diff should report additions: {d}");
        assert!(d.contains("- path:"), "diff should report removals: {d}");
        assert!(d.contains("~ path:"), "diff should report changes: {d}");
    }

    #[test]
    fn diff_identical_manifests_reports_no_changes() {
        let dir = tempdir().unwrap();
        let cas = tempdir().unwrap();
        let proj = dir.path().join("proj");
        fs::create_dir_all(&proj).unwrap();
        write(&proj.join("a.txt"), "alpha");
        let tree = provenance::build_manifest(&proj, cas.path()).unwrap();

        let policy =
            Box::new(crate::crypto::CryptoPolicyDefault {}) as Box<dyn crate::crypto::CryptoPolicy>;
        let mut paops = ParseOps::new(policy).unwrap();
        paops.io.casdir = cas.path().to_path_buf();
        let p1 = dir.path().join("a.ept");
        let p2 = dir.path().join("b.ept");
        let mut w = std::io::BufWriter::new(std::fs::File::create(&p1).unwrap());
        etree::tree_write(&mut w, &tree, &mut paops).unwrap();
        let mut w = std::io::BufWriter::new(std::fs::File::create(&p2).unwrap());
        etree::tree_write(&mut w, &tree, &mut paops).unwrap();

        let d = diff_manifests(&p1, &p2).unwrap();
        assert_eq!(d, "(no changes)\n");
    }

    // Silence unused-import warnings when PathBuf isn't otherwise
    // exercised in unit-test paths.
    #[test]
    #[allow(dead_code)]
    fn _pathbuf_in_scope() {
        let _: std::path::PathBuf = std::path::PathBuf::new();
    }
}
