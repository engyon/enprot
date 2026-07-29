// Link directives for C deps that rnp-rs's build.rs doesn't emit.
//
// On Windows MSVC: always emit (pkg-config is unavailable).
// On Linux/macOS cross-compile (Docker): emit when ENPRO_STATIC_LINK
// is set (the pre-build scripts set it in the Docker image).
// On Linux/macOS native: don't emit — pkg-config handles linking.

fn main() {
    let static_link = cfg!(target_os = "windows") || std::env::var("ENPRO_STATIC_LINK").is_ok();

    if static_link && let Ok(prefix) = std::env::var("PREFIX") {
        let libdir = format!("{}/lib", prefix.replace('\\', "/"));
        println!("cargo:rustc-link-search=native={}", libdir);

        // Transitive deps of librnp that rnp-rs's build.rs doesn't
        // emit (it only links rnp itself).
        println!("cargo:rustc-link-lib=static=json-c");
        println!("cargo:rustc-link-lib=static=sexpp");
        println!("cargo:rustc-link-lib=static=bzip2");
        println!("cargo:rustc-link-lib=static=zlib");

        // Botan is built with GCC on Linux/mingw and links against
        // libstdc++. MSVC links the C++ runtime automatically.
        if cfg!(target_os = "linux") {
            println!("cargo:rustc-link-lib=static=stdc++");
        }
    }
}
