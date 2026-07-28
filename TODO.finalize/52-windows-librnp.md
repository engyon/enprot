# 52 — Windows CI restored

**Priority**: P1
**Status**: done

Windows is back in the CI matrix. `ci/install.ps1` now builds the full
dependency stack (Botan + json-c + librnp) from source on Windows MSVC,
matching what `ci/install.sh` does on Linux/macOS.

The earlier decision to drop Windows was wrong. rnp-rs is required,
and rnp-rs needs librnp at build time — but that's a solvable build
problem, not a reason to drop a platform. librnp builds cleanly on
Windows via CMake + MSVC; the only wrinkle is that librnp also needs
json-c, which we now build in the same install script.

## What's in install.ps1 now

1. Botan (static, MT runtime) — unchanged.
2. **JSON-C 0.17** (new) — built static via CMake, matching MT runtime.
3. **librnp 0.18.1** (new) — built static via CMake, picking up the
   just-built Botan + JSON-C. Submodules initialized (sexpp is bundled).
4. Sets `RNP_INCLUDE_DIR` + `RNP_LIB_DIR` so rnp-rs's build.rs finds
   the headers and static lib.
5. Writes a `.cargo/config` that static-links `botan-3` and `rnp-0`
   into the enprot binary.

## Acceptance criteria

- [x] Windows restored to test matrix
- [x] `ci/install.ps1` builds botan + json-c + librnp
- [x] `cargo build` + `cargo test` pass on windows-latest
- [x] README documents Windows install steps (via PowerShell script)
