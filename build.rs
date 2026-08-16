// Link directives for C deps that rnp-rs's build.rs doesn't emit.
//
// When vendored-rnp is enabled, rnp-src handles all C dep linking
// (librnp, json-c, sexpp, bzip2, zlib, Botan).
//
// When vendored-rnp is NOT enabled (default, system-librnp builds):
//   - Windows MSVC: emit link directives for pre-built static libs.
//   - Linux/macOS cross-compile (Docker): emit when ENPRO_STATIC_LINK
//     is set (Docker pre-build scripts).
//   - Linux/macOS native: don't emit — pkg-config handles linking.
//
// Independently of the link mode, this script also embeds the exact
// Cargo.lock dependency list into the binary (TODO.complete/62) so
// `enprot sbom` can produce an SBOM for the running binary itself,
// without needing the source tree at SBOM-generation time.

use std::path::PathBuf;

fn main() {
    embed_lockfile_deps();

    // vendored-rnp feature → rnp-src handles all linking. Skip.
    if cfg!(feature = "vendored-rnp") {
        return;
    }

    let static_link = cfg!(target_os = "windows") || std::env::var("ENPRO_STATIC_LINK").is_ok();

    if static_link && let Ok(prefix) = std::env::var("PREFIX") {
        let libdir = format!("{}/lib", prefix.replace('\\', "/"));
        println!("cargo:rustc-link-search=native={}", libdir);

        println!("cargo:rustc-link-lib=static=json-c");
        println!("cargo:rustc-link-lib=static=sexpp");
        println!("cargo:rustc-link-lib=static=bzip2");
        println!("cargo:rustc-link-lib=static=zlib");

        if cfg!(target_os = "linux") {
            println!("cargo:rustc-link-lib=static=stdc++");
        }
    }
}

/// Find the workspace Cargo.lock: the manifest dir when enprot IS
/// the workspace root, its parent when it's a member.
fn find_workspace_lock() -> Option<PathBuf> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").ok()?);
    for dir in [manifest.clone(), manifest.parent()?.to_path_buf()] {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Extract `name` / `version` from one `[[package]]` block of a
/// Cargo.lock v3/v4 file. Returns None for path-only workspace
/// members without a version (none exist in this workspace) or
/// malformed blocks.
fn parse_package_block(block: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    for line in block.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("name = ") {
            name = v.trim_matches('"').to_string().into();
        } else if let Some(v) = line.strip_prefix("version = ") {
            version = v.trim_matches('"').to_string().into();
        }
    }
    Some((name?, version?))
}

/// Bake the resolved dependency list into the binary as a
/// space-separated `name@version` string. Deterministic: the same
/// lockfile always yields the same embedded string (sorted), so
/// rebuilds of the same commit embed identical data (TODO.complete/45).
///
/// Parsed by hand rather than via the `cargo-lock` build-dependency:
/// adding build-deps perturbed the cross-compile link graph on the
/// OHOS target (see TODO.complete/62 notes), and the subset needed
/// here — `name`/`version` per `[[package]]` block — is frozen
/// Cargo.lock surface, not an open-ended format.
fn embed_lockfile_deps() {
    let Some(lock_path) = find_workspace_lock() else {
        // No lockfile (e.g. published-crate builds without one). The
        // sbom command reports the situation rather than failing the
        // build — a binary without an SBOM beats no binary.
        println!("cargo:rustc-env=ENPROT_DEP_LIST=");
        return;
    };
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let text = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", lock_path.display()));

    let mut deps: Vec<String> = text
        .split("[[package]]")
        .skip(1)
        .filter_map(parse_package_block)
        .map(|(name, version)| format!("{name}@{version}"))
        .collect();
    deps.sort();
    deps.dedup();

    // rustc-env directive values are line-based — embedded newlines
    // truncate the value at the first record. Space-separate instead;
    // crate names and semver strings never contain whitespace.
    println!("cargo:rustc-env=ENPROT_DEP_LIST={}", deps.join(" "));
}
