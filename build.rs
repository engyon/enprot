// On Windows, static libraries (botan-3, json-c, sexpp, rnp, bzip2,
// zlib) need explicit link directives. rnp-rs's build.rs handles rnp
// itself but not its transitive deps (json-c, sexpp, bzip2, zlib).
// This build.rs emits the missing link directives — only for enprot,
// not for dependency build scripts (unlike [target.<triple>] rustflags
// which would break dep compilation).

fn main() {
    if cfg!(target_os = "windows") {
        // Only emit if the env var is set (install.ps1 sets it).
        if let Ok(prefix) = std::env::var("PREFIX") {
            let libdir = format!("{}/lib", prefix.replace('\\', "/"));
            println!("cargo:rustc-link-search=native={}", libdir);
            // Transitive deps of librnp that rnp-rs's build.rs doesn't emit.
            println!("cargo:rustc-link-lib=static=json-c");
            println!("cargo:rustc-link-lib=static=sexpp");
            println!("cargo:rustc-link-lib=static=bzip2");
            println!("cargo:rustc-link-lib=static=zlib");
        }
    }
}
