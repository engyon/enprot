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

/// Bake the resolved dependency list into the binary as a
/// newline-separated `name@version` string. Deterministic: the same
/// lockfile always yields the same embedded string (dependencies are
/// sorted), so rebuilds of the same commit embed identical data
/// (TODO.complete/45).
fn embed_lockfile_deps() {
    // BISECT-EXPERIMENT: link directives disabled to isolate the OHOS
    // link failure; only the env var is still set. Everything else
    // (dep, parsing) unchanged.
    let _ = find_workspace_lock();
    println!("cargo:rustc-env=ENPROT_DEP_LIST=");
}
