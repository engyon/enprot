# 51 — OHOS (OpenHarmony) build target

**Priority**: P1
**Status**: implemented (CI verification pending first run)

## Problem

OHOS (OpenHarmony / Huawei HarmonyOS) is a musl-based arm64 Linux
target. Two related triples are in play:

- **Rust target**: `aarch64-unknown-linux-ohos` (with `unknown`
  vendor field — Rust requires it). Tier 2 with host tools since
  Rust 1.71. enprot's MSRV 1.85, so it's available.
- **NDK triple**: `aarch64-linux-ohos` (no vendor field). Used for
  the sysroot path (`llvm-19/sysroot/aarch64-linux-ohos/`), the
  `--target=` flag passed to clang, and the install-prefix name.

The NDK clang binaries are named after the **Rust** triple
(`aarch64-unknown-linux-ohos-clang++`) — clang normalizes the two
forms internally so `--target=aarch64-linux-ohos` works.

Adding OHOS as a build target unlocks enprot for HarmonyOS devices
(phones, tablets, IoT).

enprot depends on:

- **Botan 3** (C++): the crypto provider. Must be cross-compiled for
  OHOS and statically linked (avoids `.so` code-signing requirements
  for app distribution; enprot is a CLI, not a loaded library).
- **aes-gcm-siv** (pure Rust): no system deps; works with the right
  target triple out of the box.

## Architecture

Reference impl distilled from shipping `libpng-ruby` 1.6.58.6 for
`aarch64-linux-ohos` (see `docs/ohos-porting-guide.md` once written;
original gist: https://gist.github.com/ronaldtse/78b6b610cfa00ead8fb3b8f935afaa3b).

### NDK pieces

Two downloads from OpenHarmony's `daily_build` API:

- `ohos-sdk-public` (~3.2 GB): `toolchains/lib/binary-sign-tool`,
  `native/build/cmake/ohos.toolchain.cmake`, `native/llvm/bin/clang`.
- `LLVM-19` (~670 MB): `llvm-linux-x86_64.tar.gz` (clang itself,
  x86_64 ELF even though target is arm64) + `ohos-sysroot.tar.gz`
  (per-arch sysroots).

### The two-sysroots problem

The SDK ships a MULTIARCH sysroot at
`ohos-sdk/linux/native/sysroot/usr/include/<arch>/bits/...`; the
toolchain expects a PER-ARCH sysroot at
`llvm-19/sysroot/aarch64-linux-ohos/usr/include/bits/...`.

Fix: replace the SDK's multiarch sysroot with a relative symlink to
the LLVM-19 per-arch sysroot. **Must be relative** — absolute targets
break inside docker containers that mount at a different path.

### Botan cross-compile

Botan uses `configure.py` (not CMake). For OHOS:

```sh
./configure.py \
  --cc=clang \
  --cc-bin=$NDK/llvm/bin/aarch64-unknown-linux-ohos-clang++ \
  --cc-abi-flags="--target=aarch64-linux-ohos --sysroot=$SYSROOT" \
  --cpu=aarch64 \
  --os=linux \
  --build-targets=static \
  --minimized-build \
  --enable-modules=$BOTAN_MODULES \
  --prefix=$PREFIX/ohos-aarch64 \
  --without-documentation
make -j$(nproc)
make install
```

Static build (`--build-targets=static`) sidesteps `.so` code-signing.

### Rust build

```sh
# Rust target uses "unknown" vendor field; NDK triple doesn't.
RUST_TARGET=aarch64-unknown-linux-ohos
NDK_TRIPLE=aarch64-linux-ohos

rustup target add $RUST_TARGET
export PKG_CONFIG_PATH=$PREFIX/ohos-aarch64/lib/pkgconfig
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_SYSROOT_DIR=$PREFIX/ohos-sdk/linux/native/sysroot
# Cargo env var name is uppercased RUST_TARGET with _ for -.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER=$PREFIX/llvm-19/llvm/bin/aarch64-unknown-linux-ohos-clang++
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUSTFLAGS="-C link-arg=--target=$NDK_TRIPLE -C link-arg=--sysroot=$PREFIX/ohos-sdk/linux/native/sysroot"
cargo build --target $RUST_TARGET --release
```

## CI topology

Per the gist, the OHOS NDK binaries are x86_64 ELF. Run on
`ubuntu-latest`:

1. Install cmake, ninja, jq, unzip, curl.
2. `ci/setup-ohos-ndk.sh --prefix ext/ohos` (cached via
   `actions/cache@v4` keyed on script hash).
3. `ci/build-botan-ohos.sh --prefix ext/ohos --sysroot ext/ohos/...`.
4. `cargo build --target aarch64-linux-ohos --release`.
5. Verify in `ghcr.io/hqzing/dockerharmony:latest` (real OHOS
   userland, runs natively on arm64 hosts or via qemu binfmt on x86_64).
   - Smoke test: `ci/ohos-smoke.c` round-trips a hash + AEAD via
     Botan's C API to confirm the static lib actually links and runs.

## What this does NOT cover

- **HNP packaging** for production deployment on HarmonyOS PCs
  (see https://www.cnblogs.com/yangykaifa/p/19479007). That's a
  separate concern once the binary builds.
- **Real OHOS hardware** verification. dockerharmony runs OHOS
  rootfs on a Linux kernel; real devices may have additional
  kernel-level signing or SELinux constraints.
- **armv7 / x86_64 OHOS** targets. `aarch64-linux-ohos` is the
  dominant target; the others can be added later by extending the
  matrix.

## Acceptance criteria

- [ ] `ci/setup-ohos-ndk.sh` downloads NDK + LLVM-19, sets up
      relative sysroot symlink, idempotent + cached. Accepts both
      `--ndk-triple` (sysroot path + clang `--target=` flag) and
      `--rust-target` (rustup + cargo `--target`).
- [ ] `ci/build-botan-ohos.sh` produces a static `libbotan-3.a`
      for the OHOS arm64 target.
- [ ] `cargo build --target aarch64-unknown-linux-ohos --release`
      produces an `enprot` binary.
- [ ] `.github/workflows/ohos.yml` runs end-to-end on CI.
- [ ] dockerharmony smoke test links Botan static + runs a hash/AEAD
      round-trip, exits 0.
- [ ] README documents the OHOS build path.
