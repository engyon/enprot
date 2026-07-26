#!/usr/bin/env bash
# Cross-compile Botan 3 for OHOS (aarch64-linux-ohos) as a static library.
# Static build avoids .so code-signing requirements (enprot is a CLI binary,
# not a loaded library).
#
# Prereq: ci/setup-ohos-ndk.sh has been run with --prefix=$PREFIX.
#
# Usage:
#   ci/build-botan-ohos.sh --prefix ext/ohos --botan-version 3.7.0 \
#                          [--triple aarch64-linux-ohos]
#
# Outputs:
#   $PREFIX/botan-build/             # source + build artifacts
#   $PREFIX/ohos-aarch64/            # installed static lib + headers + pkg-config
#     lib/libbotan-3.a
#     include/botan-3/...
#     lib/pkgconfig/botan-3.pc

set -euo pipefail

PREFIX=""
BOTAN_VERSION="3.7.0"
TRIPLE="${OHOS_TRIPLE:-aarch64-linux-ohos}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)        PREFIX="$2"; shift 2;;
    --botan-version) BOTAN_VERSION="$2"; shift 2;;
    --triple)        TRIPLE="$2"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

[ -n "$PREFIX" ] || { echo "usage: $0 --prefix <dir>" >&2; exit 1; }
PREFIX="$(cd "$PREFIX" && pwd)"

SYSROOT="$PREFIX/ohos-sdk/linux/native/sysroot"
TOOLCHAIN_CMAKE="$PREFIX/ohos-sdk/linux/native/build/cmake/ohos.toolchain.cmake"
NDK_CLANGXX="$PREFIX/llvm-19/llvm/bin/${TRIPLE//-/_}-clang++"

for f in "$SYSROOT" "$TOOLCHAIN_CMAKE" "$NDK_CLANGXX"; do
  [ -e "$f" ] || { echo "missing NDK piece: $f" >&2; exit 1; }
done

# CPU mapping for Botan's --cpu flag.
case "$TRIPLE" in
  aarch64-linux-ohos) BOTAN_CPU=aarch64;;
  armv7-linux-ohos)   BOTAN_CPU=arm32;;
  x86_64-linux-ohos)  BOTAN_CPU=x86_64;;
  *) echo "unknown triple: $TRIPLE" >&2; exit 1;;
esac

INSTALL_PREFIX="$PREFIX/ohos-${TRIPLE%%-*}"
BUILD_DIR="$PREFIX/botan-build"
SRC_DIR="$BUILD_DIR/botan"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d "$SRC_DIR" ]; then
  git clone --depth 1 --branch "$BOTAN_VERSION" \
    https://github.com/randombit/botan "$SRC_DIR"
fi

# BOTAN_MODULES matches ci/botan-modules.
BOTAN_MODULES="$(cat "$(dirname "$0")/botan-modules")"

cd "$SRC_DIR"

# Configure for cross-compile. Botan uses --os=linux because OHOS is
# musl/Linux-based; the target-specific bits come from --cc-abi-flags.
# --build-targets=static produces libbotan-3.a (no .so to code-sign).
python3 ./configure.py \
  --cc=clang \
  --cc-bin="$NDK_CLANGXX" \
  --cc-abi-flags="--target=$TRIPLE --sysroot=$SYSROOT" \
  --cpu="$BOTAN_CPU" \
  --os=linux \
  --build-targets=static \
  --minimized-build \
  --enable-modules="$BOTAN_MODULES" \
  --prefix="$INSTALL_PREFIX" \
  --without-documentation \
  --cxxflags="-std=c++20"

make -j"$(nproc)"
make install

# Sanity check.
if [ ! -f "$INSTALL_PREFIX/lib/libbotan-3.a" ]; then
  echo "libbotan-3.a not produced" >&2
  exit 1
fi

echo
echo "Botan $BOTAN_VERSION static built for $TRIPLE"
echo "  install prefix: $INSTALL_PREFIX"
echo "  lib:            $INSTALL_PREFIX/lib/libbotan-3.a"
echo "  pkg-config:     $INSTALL_PREFIX/lib/pkgconfig/botan-3.pc"
