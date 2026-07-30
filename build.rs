// Link directives for C deps that rnp-rs's build.rs doesn't emit.
//
// When vendored-rnp is enabled, rnp-src handles all C dep linking
// (librnp, json-c, sexpp, bzip2, zlib, Botan). enprot's build.rs
// does nothing.
//
// When vendored-rnp is NOT enabled (default, system-librnp builds):
//   - Windows MSVC: emit link directives for pre-built static libs.
//   - Linux/macOS cross-compile (Docker): emit when ENPRO_STATIC_LINK
//     is set (Docker pre-build scripts).
//   - Linux/macOS native: don't emit — pkg-config handles linking.

fn main() {
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
