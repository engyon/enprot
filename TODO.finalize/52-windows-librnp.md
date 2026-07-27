# 52 — Windows build needs librnp via vcpkg

**Priority**: P1
**Status**: specified

## Problem

rnp-rs (now a required dep, see TODO.finalize/51) requires `librnp`
at build time. On Linux and macOS, `ci/build-librnp.sh` clones
`rnpgp/rnp` at v0.18.1 and builds via CMake + the system botan.

On Windows there's no analogous path. rnp-rs's `build.rs` looks for
`<rnp/rnp.h>` at `/usr/include` (hardcoded Unix path); on Windows
that doesn't exist, so any `cargo build` fails with
"Could not find <rnp/rnp.h> under /usr/include".

The test matrix was reduced to ubuntu-latest + macos-latest in
`.github/workflows/tests.yml` to keep CI green. Restoring Windows
support requires librnp to be installable on Windows.

## Approach: vcpkg port

The cleanest Windows path is a vcpkg port that:
1. Mirrors the build flags used in `ci/build-librnp.sh`
   (`-DCRYPTO_BACKEND=botan`, etc.).
2. Depends on botan, json-c, zlib (all already in vcpkg).
3. Installs headers + `rnp.lib` + `rnp.dll` to a standard vcpkg
   layout that rnp-rs's `build.rs` can find via `RNP_INCLUDE_DIR` /
   `RNP_LIB_DIR` env vars.

The rnp-rs build.rs accepts `RNP_INCLUDE_DIR` and `RNP_LIB_DIR`, so
once vcpkg installs librnp we just set those env vars in the Windows
job:

```yaml
env:
  RNP_INCLUDE_DIR: $VCPKG_ROOT/installed/x64-windows/include
  RNP_LIB_DIR: $VCPKG_ROOT/installed/x64-windows/lib
```

## Alternative: vendored feature

rnp-rs has a `vendored` Cargo feature that builds librnp from a git
submodule via CMake. From a crates.io dep this fails because the
submodule isn't initialized in the published crate. From a git dep
(`rnp-rs = { git = "...", features = ["vendored"] }`) it could work
but pulls in cmake + botan + json-c + zlib as transitive build deps
on every consumer, not just Windows.

## Acceptance criteria

- [ ] librnp available on Windows via vcpkg or equivalent
- [ ] Windows job restored to test matrix
- [ ] `cargo build` + `cargo test` pass on windows-latest
- [ ] README documents Windows install steps for end users
