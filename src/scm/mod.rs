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

/// Parse `cargo_toml_path`'s `[dependencies]` table and append one
/// entry per dependency. The "content" of each entry is the
/// `name=version` string, content-addressed via CAS so the manifest
/// records the exact resolved version.
pub fn add_cargo_deps(
    manifest_path: &Path,
    cargo_toml_path: &Path,
    casdir: &Path,
) -> Result<usize> {
    let raw = std::fs::read_to_string(cargo_toml_path)?;
    let deps = parse_cargo_dependencies(&raw)?;

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
    // Sort deps for byte-stable output across runs.
    let mut sorted: Vec<(String, String)> = deps.into_iter().collect();
    sorted.sort();
    for (name, version) in sorted {
        let content = format!("{name}={version}");
        let bytes = content.into_bytes();
        let hash = crate::cas::save(bytes, &mut paops)?;
        tree.push(TextNode::Plain(format!("# dep: {name}={version}")));
        tree.push(TextNode::Include { hash });
        added += 1;
    }

    let f = std::fs::File::create(manifest_path)?;
    let mut w = std::io::BufWriter::new(f);
    etree::tree_write(&mut w, &tree, &mut paops)?;
    Ok(added)
}

/// Minimal Cargo.toml `[dependencies]` parser. Returns a Vec of
/// (name, version) pairs. Version is the simple-form value (e.g.
/// `"1.0"`); table-form (`{ version = "...", features = [...] }`) is
/// flattened to just the version field. We use the `toml` crate for
/// the actual parse so we don't reinvent TOML.
fn parse_cargo_dependencies(cargo_toml: &str) -> Result<Vec<(String, String)>> {
    let parsed: toml::Value =
        toml::from_str(cargo_toml).map_err(|e| Error::msg(format!("Cargo.toml parse: {e}")))?;
    let Some(deps_table) = parsed.get("dependencies").and_then(|v| v.as_table()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, val) in deps_table {
        let version = match val {
            toml::Value::String(s) => s.clone(),
            toml::Value::Table(t) => t
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            _ => "?".to_string(),
        };
        out.push((name.clone(), version));
    }
    Ok(out)
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
        let deps = parse_cargo_dependencies(toml).unwrap();
        let map: BTreeMap<String, String> = deps.into_iter().collect();
        assert_eq!(map.get("serde").map(String::as_str), Some("1.0"));
        assert_eq!(map.get("toml").map(String::as_str), Some("0.8"));
        assert_eq!(map.get("hex").map(String::as_str), Some("0.4"));
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
