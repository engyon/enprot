#!/usr/bin/env bash
# OHOS NDK setup. Downloads ohos-sdk-public + LLVM-19 from the
# OpenHarmony daily_build API, extracts them, and replaces the SDK's
# MULTIARCH sysroot with a relative symlink to the LLVM-19 PER-ARCH
# sysroot (per docs/ohos-porting-guide.md).
#
# Reference impl: https://gist.github.com/ronaldtse/78b6b610cfa00ead8fb3b8f935afaa3b
#
# Usage:
#   ci/setup-ohos-ndk.sh --prefix ext/ohos [--ndk-triple aarch64-linux-ohos]
#
# Outputs (under $PREFIX):
#   ohos-sdk/linux/native/llvm/bin/clang          # NDK clang (x86_64 ELF)
#   ohos-sdk/linux/native/build/cmake/ohos.toolchain.cmake
#   ohos-sdk/linux/native/sysroot                 # symlink → llvm-19 sysroot
#   ohos-sdk/linux/toolchains/lib/binary-sign-tool
#   llvm-19/sysroot/<ndk-triple>/                 # per-arch sysroot
#   llvm-19/llvm/bin/<rust-triple>-clang++        # e.g. aarch64-unknown-linux-ohos-clang++
#
# Environment:
#   OHOS_ARCH     arm64-v8a (default) | armv7-v8a | x86_64-v8a
#   NDK_TRIPLE    aarch64-linux-ohos (default) | armv7-linux-ohos | x86_64-linux-ohos
#                 (used for sysroot path + --target= flag)
#   RUST_TARGET   aarch64-unknown-linux-ohos (default) | armv7-unknown-linux-ohos | ...
#                 (used for rustup target add + cargo --target; includes "unknown" vendor)

set -euo pipefail

PREFIX=""
ARCH="${OHOS_ARCH:-arm64-v8a}"
NDK_TRIPLE="${NDK_TRIPLE:-aarch64-linux-ohos}"
RUST_TARGET="${RUST_TARGET:-aarch64-unknown-linux-ohos}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      PREFIX="$2"; shift 2;;
    --arch)        ARCH="$2"; NDK_TRIPLE=$(arch_to_ndk_triple "$2"); RUST_TARGET=$(ndk_to_rust_triple "$NDK_TRIPLE"); shift 2;;
    --ndk-triple)  NDK_TRIPLE="$2"; RUST_TARGET=$(ndk_to_rust_triple "$2"); shift 2;;
    --rust-target) RUST_TARGET="$2"; shift 2;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

arch_to_ndk_triple() {
  case "$1" in
    arm64-v8a)   echo "aarch64-linux-ohos";;
    armeabi-v7a) echo "armv7-linux-ohos";;
    x86-64)      echo "x86_64-linux-ohos";;
    *) echo "unknown OHOS_ARCH: $1" >&2; exit 1;;
  esac
}

# Rust target triples include the "unknown" vendor field; NDK triples don't.
ndk_to_rust_triple() {
  case "$1" in
    aarch64-linux-ohos) echo "aarch64-unknown-linux-ohos";;
    armv7-linux-ohos)   echo "armv7-unknown-linux-ohos";;
    x86_64-linux-ohos)  echo "x86_64-unknown-linux-ohos";;
    *) echo "unknown NDK triple: $1" >&2; exit 1;;
  esac
}

if [ -z "$PREFIX" ]; then
  echo "usage: $0 --prefix <dir>" >&2
  exit 1
fi

mkdir -p "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)"

# Idempotent: if the final symlink exists, assume setup completed.
if [ -L "$PREFIX/ohos-sdk/linux/native/sysroot" ]; then
  echo "OHOS NDK already set up at $PREFIX"
  exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need curl; need jq; need unzip; need tar

# --- Download NDK pieces from the OpenHarmony daily_build API -----------
# The CDN resets connections intermittently; --retry-all-errors is required.

query_component() {
  local component="$1"
  curl --retry 5 --retry-delay 5 --retry-all-errors -fsSL \
    'https://dcp.openharmony.cn/api/daily_build/build/list/component' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Content-Type: application/json' \
    --data-raw '{"projectName":"openharmony","branch":"master","pageNum":1,"pageSize":10,"deviceLevel":"","component":"'"${component}"'","type":1,"startTime":"2025080100000000","endTime":"20990101235959","sortType":"","sortField":"","hardwareBoard":"","buildStatus":"success","buildFailReason":"","withDomain":1}'
}

SDK_URL=$(query_component "ohos-sdk-public" | jq -r '.data.list.dataList[0].obsPath')
LLVM_URL=$(query_component "LLVM-19"        | jq -r '.data.list.dataList[0].obsPath')

if [ -z "$SDK_URL" ] || [ "$SDK_URL" = "null" ]; then
  echo "failed to resolve ohos-sdk-public URL" >&2; exit 1;
fi
if [ -z "$LLVM_URL" ] || [ "$LLVM_URL" = "null" ]; then
  echo "failed to resolve LLVM-19 URL" >&2; exit 1;
fi

echo "Downloading ohos-sdk-public from $SDK_URL"
curl --retry 5 --retry-delay 5 --retry-all-errors -fSL "$SDK_URL" -o "$PREFIX/ohos-sdk.zip"

echo "Downloading LLVM-19 from $LLVM_URL"
curl --retry 5 --retry-delay 5 --retry-all-errors -fSL "$LLVM_URL" -o "$PREFIX/llvm-19.tar.gz"

# --- Extract ohos-sdk ---------------------------------------------------
# The zip is a tarball of zips. Extract the outer zip first, then each
# inner zip in ohos-sdk/linux/.
cd "$PREFIX"
unzip -q ohos-sdk.zip
rm -f ohos-sdk.zip

# Some releases wrap the SDK dir; normalize to ohos-sdk/.
if [ ! -d "ohos-sdk" ]; then
  # Find the top-level dir name (often "ohos-sdk" or version-stamped).
  SDK_DIR=$(find . -maxdepth 1 -type d -name 'ohos-sdk*' | head -1)
  [ -n "$SDK_DIR" ] || { echo "ohos-sdk dir not found after extraction" >&2; exit 1; }
  [ "$SDK_DIR" = "ohos-sdk" ] || mv "$SDK_DIR" ohos-sdk
fi

cd "$PREFIX/ohos-sdk/linux"
for z in *.zip; do
  [ -e "$z" ] || continue
  echo "  extracting $z"
  unzip -q "$z"
  rm -f "$z"
done

# --- Extract LLVM-19 ----------------------------------------------------
cd "$PREFIX"
mkdir -p llvm-19
tar -xzf llvm-19.tar.gz -C llvm-19 --strip-components=1
rm -f llvm-19.tar.gz

# --- Two-sysroots fix ---------------------------------------------------
# SDK ships a MULTIARCH sysroot at ohos-sdk/linux/native/sysroot/.
# Toolchain expects a PER-ARCH sysroot. Replace with a RELATIVE
# symlink to llvm-19/sysroot/<triple>.
LLVM_SYSROOT="$PREFIX/llvm-19/sysroot/$NDK_TRIPLE"
if [ ! -d "$LLVM_SYSROOT" ]; then
  echo "LLVM-19 sysroot for $NDK_TRIPLE not found at $LLVM_SYSROOT" >&2
  echo "available:" >&2
  ls "$PREFIX/llvm-19/sysroot/" >&2 || true
  exit 1
fi

cd "$PREFIX/ohos-sdk/linux/native"
rm -rf sysroot
# Relative target: resolves correctly inside docker containers that
# mount the repo at a different absolute path.
ln -s "../../../llvm-19/sysroot/$NDK_TRIPLE" sysroot

# The NDK clang binaries are named after the RUST target triple
# (with "unknown" vendor), e.g. aarch64-unknown-linux-ohos-clang++.
# Underscores separate components in the filename.
NDK_CLANGXX="$PREFIX/llvm-19/llvm/bin/${RUST_TARGET//-/_}-clang++"
if [ ! -x "$NDK_CLANGXX" ]; then
  echo "NDK clang++ not found at $NDK_CLANGXX" >&2
  echo "available in llvm-19/llvm/bin/:" >&2
  ls "$PREFIX/llvm-19/llvm/bin/" | grep -E 'clang$|clang\+\+$' >&2 || true
  exit 1
fi

echo
echo "OHOS NDK ready at $PREFIX"
echo "  rust target:     $RUST_TARGET"
echo "  ndk triple:      $NDK_TRIPLE"
echo "  toolchain cmake: $PREFIX/ohos-sdk/linux/native/build/cmake/ohos.toolchain.cmake"
echo "  clang:           $PREFIX/ohos-sdk/linux/native/llvm/bin/clang"
echo "  clang++ (NDK):   $NDK_CLANGXX"
echo "  sysroot →        $PREFIX/ohos-sdk/linux/native/sysroot"
echo "  sign tool:       $PREFIX/ohos-sdk/linux/toolchains/lib/binary-sign-tool"
