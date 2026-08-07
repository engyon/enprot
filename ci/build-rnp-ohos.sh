#!/usr/bin/env bash
# Cross-compile librnp + its C deps for OHOS (aarch64-linux-ohos) as
# static libraries. rnp-rs's build script then finds them via
# RNP_INCLUDE_DIR + RNP_LIB_DIR env vars (Explicit link mode).
#
# Why this exists: `--features vendored-rnp` would be the obvious
# choice, but vendored-rnp pulls in botan-src which doesn't honor the
# OHOS cross-compile environment (configure.py auto-detects the x86_64
# host compiler). So we build librnp the same way we build Botan:
# manually, with the NDK clang.
#
# Prereqs:
#   - ci/setup-ohos-ndk.sh has been run with --prefix=$PREFIX
#   - ci/build-botan-ohos.sh has been run (libbotan-3.a + botan-3.pc
#     must exist in $PREFIX/ohos-aarch64)
#
# Usage:
#   ci/build-rnp-ohos.sh --prefix ext/ohos \
#                        [--rnp-version 0.18.1] \
#                        [--ndk-triple aarch64-linux-ohos] \
#                        [--rust-target aarch64-unknown-linux-ohos]
#
# Outputs:
#   $PREFIX/rnp-build/             # source + build artifacts
#   $PREFIX/ohos-aarch64/          # installed lib + headers
#     lib/librnp.a
#     lib/libjson-c.a
#     lib/libsexpp.a
#     lib/libz.a
#     lib/libbz2.a
#     include/rnp/rnp.h

set -euo pipefail

PREFIX=""
RNP_VERSION="0.18.1"
NDK_TRIPLE="${NDK_TRIPLE:-aarch64-linux-ohos}"
RUST_TARGET="${RUST_TARGET:-aarch64-unknown-linux-ohos}"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)        PREFIX="$2"; shift 2;;
    --rnp-version)   RNP_VERSION="$2"; shift 2;;
    --ndk-triple)    NDK_TRIPLE="$2"; shift 2;;
    --rust-target)   RUST_TARGET="$2"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

[ -n "$PREFIX" ] || { echo "usage: $0 --prefix <dir>" >&2; exit 1; }
PREFIX="$(cd "$PREFIX" && pwd)"

SYSROOT="$PREFIX/llvm-19/sysroot/$NDK_TRIPLE"
NDK_CLANG="$PREFIX/llvm-19/llvm/bin/${RUST_TARGET}-clang"
NDK_CLANGXX="$PREFIX/llvm-19/llvm/bin/${RUST_TARGET}-clang++"
NDK_AR="$PREFIX/llvm-19/llvm/bin/llvm-ar"
NDK_RANLIB="$PREFIX/llvm-19/llvm/bin/llvm-ranlib"

INSTALL_PREFIX="$PREFIX/ohos-${NDK_TRIPLE%%-*}"
BUILD_DIR="$PREFIX/rnp-build"

for f in "$SYSROOT" "$NDK_CLANG" "$NDK_CLANGXX" "$NDK_AR" "$NDK_RANLIB"; do
  [ -e "$f" ] || { echo "missing NDK piece: $f" >&2; exit 1; }
done

# Common cross-compile flags. --target/$NDK_TRIPLE tells clang which
# ABI to emit; --sysroot tells it where to find libc/libcxx headers.
CROSS_CFLAGS="--target=$NDK_TRIPLE --sysroot=$SYSROOT -O2 -fPIC"
CROSS_LDFLAGS="--target=$NDK_TRIPLE --sysroot=$SYSROOT"

# Toolchain file for CMake-based deps (json-c, rnp). CMake's cross
# compile story is "toolchain file" — a .cmake file that sets
# CMAKE_C_COMPILER, CMAKE_CXX_COMPILER, CMAKE_SYSTEM_NAME, sysroot, etc.
TOOLCHAIN_FILE="$BUILD_DIR/toolchain.cmake"
mkdir -p "$BUILD_DIR"
cat > "$TOOLCHAIN_FILE" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER $NDK_CLANG)
set(CMAKE_CXX_COMPILER $NDK_CLANGXX)
set(CMAKE_AR $NDK_AR)
set(CMAKE_RANLIB $NDK_RANLIB)
set(CMAKE_SYSROOT $SYSROOT)
set(CMAKE_FIND_ROOT_PATH $INSTALL_PREFIX $SYSROOT)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_C_FLAGS "$CROSS_CFLAGS")
set(CMAKE_CXX_FLAGS "$CROSS_CFLAGS")
set(CMAKE_EXE_LINKER_FLAGS "$CROSS_LDFLAGS")
set(CMAKE_SHARED_LINKER_FLAGS "$CROSS_LDFLAGS")
set(CMAKE_STATIC_LINKER_FLAGS "")
EOF

export CC="$NDK_CLANG"
export CXX="$NDK_CLANGXX"
export AR="$NDK_AR"
export RANLIB="$NDK_RANLIB"
export CFLAGS="$CROSS_CFLAGS"
export CXXFLAGS="$CROSS_CFLAGS"
export LDFLAGS="$CROSS_LDFLAGS"

cd "$BUILD_DIR"

# -------------------------------------------------------------------
# 1. zlib (rnp's find_package(ZLIB) REQUIRED)
# -------------------------------------------------------------------
ZLIB_VERSION="1.3.1"
if [ ! -d "zlib-$ZLIB_VERSION" ]; then
  curl -fsSL "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" \
    -o "zlib-$ZLIB_VERSION.tar.gz"
  tar -xzf "zlib-$ZLIB_VERSION.tar.gz"
fi
mkdir -p "zlib-$ZLIB_VERSION/build"
cmake -S "zlib-$ZLIB_VERSION" -B "zlib-$ZLIB_VERSION/build" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
cmake --build "zlib-$ZLIB_VERSION/build" --parallel "$(nproc)"
cmake --install "zlib-$ZLIB_VERSION/build"

# -------------------------------------------------------------------
# 2. bzip2 (rnp's find_package(BZip2) REQUIRED, even with ENABLE_BZIP2=OFF)
# -------------------------------------------------------------------
BZIP2_VERSION="1.0.8"
if [ ! -d "bzip2-$BZIP2_VERSION" ]; then
  curl -fsSL "https://github.com/libarchive/bzip2/archive/refs/tags/bzip2-$BZIP2_VERSION.tar.gz" \
    -o "bzip2-$BZIP2_VERSION.tar.gz"
  tar -xzf "bzip2-$BZIP2_VERSION.tar.gz"
  mv "bzip2-bzip2-$BZIP2_VERSION" "bzip2-$BZIP2_VERSION"
fi
cd "bzip2-$BZIP2_VERSION"
make clean || true
# bzip2's Makefile uses $(CC) directly; we set CC=$NDK_CLANG env above.
# Add -fPIC (needed for static archive that gets linked into a .so later).
make libbz2.a CFLAGS="$CFLAGS -fPIC" CC="$CC" AR="$AR" RANLIB="$RANLIB"
install -m 644 libbz2.a "$INSTALL_PREFIX/lib/"
install -m 644 bzlib.h "$INSTALL_PREFIX/include/"
cd "$BUILD_DIR"

# -------------------------------------------------------------------
# 3. json-c (librnp hard dep)
# -------------------------------------------------------------------
if [ ! -d "json-c-src" ]; then
  git clone --depth 1 --branch json-c-0.17-20230812 \
    https://github.com/json-c/json-c.git json-c-src
fi
mkdir -p json-c-src/build
cmake -S json-c-src -B json-c-src/build \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
cmake --build json-c-src/build --parallel "$(nproc)"
cmake --install json-c-src/build

# -------------------------------------------------------------------
# 4. libsexpp (rnp submodule; needed for cmake build)
# -------------------------------------------------------------------
if [ ! -d "sexpp-src" ]; then
  git clone --depth 1 --branch 0.1.1 \
    https://github.com/rnpgp/sexpp.git sexpp-src || \
  git clone --depth 1 https://github.com/rnpgp/sexpp.git sexpp-src
fi
mkdir -p sexpp-src/build
cmake -S sexpp-src -B sexpp-src/build \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DSEXPP_BUILD_TESTS=OFF \
  -DSEXPP_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
# Build only the sexpp library target — not the tests. CMake's
# gtest_discover_tests tries to execute cross-compiled binaries
# during the build phase, which fails (ELF binary run as shell script).
# --target sexpp skips the test binary entirely.
cmake --build sexpp-src/build --target sexpp --parallel "$(nproc)"
# Manual install: cmake --install fails because it tries to install
# bin/sexpp which we didn't build (--target sexpp = library only).
# Hand-copy what rnp's find_package(sexpp) needs:
#   - lib/libsexpp.a
#   - include/sexpp/*.h
#   - lib/cmake/sexpp/sexpp-config.cmake (+ targets files)
install -m 755 -d "$INSTALL_PREFIX/lib/cmake/sexpp"
find sexpp-src/build -name 'libsexpp.a' -exec cp -f {} "$INSTALL_PREFIX/lib/" \;
cp -rf sexpp-src/include/sexpp "$INSTALL_PREFIX/include/"
cp -f sexpp-src/build/cmake/sexpp-config.cmake "$INSTALL_PREFIX/lib/cmake/sexpp/" 2>/dev/null || true
cp -f sexpp-src/build/cmake/sexpp-targets*.cmake "$INSTALL_PREFIX/lib/cmake/sexpp/" 2>/dev/null || true
# Rewrite the targets-release.cmake to remove the bin/sexpp reference
# that would fail at find_package(sexpp) time on cross-compile.
sed -i '/bin\/sexpp/d' "$INSTALL_PREFIX/lib/cmake/sexpp/sexpp-targets-release.cmake" 2>/dev/null || true

# -------------------------------------------------------------------
# 5. rnp itself
# -------------------------------------------------------------------
if [ ! -d "rnp-src" ]; then
  git clone --branch "v$RNP_VERSION" --depth 1 \
    https://github.com/rnpgp/rnp.git rnp-src
  cd rnp-src
  git submodule update --init --recursive
  cd "$BUILD_DIR"
fi
mkdir -p rnp-src/build
cmake -S rnp-src -B rnp-src/build \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DENABLE_DOC=OFF \
  -DENABLE_PQC=OFF \
  -DENABLE_CRYPTO_REFRESH=OFF \
  -DCRYPTO_BACKEND=botan \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
  -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX" \
  -DBotan3_DIR="$INSTALL_PREFIX/lib/cmake/Botan-3" \
  -Djson-c_DIR="$INSTALL_PREFIX/lib/cmake/json-c" \
  -Dsexpp_DIR="$INSTALL_PREFIX/lib/cmake/sexpp"
cmake --build rnp-src/build --parallel "$(nproc)"
cmake --install rnp-src/build

# Sanity check.
for f in \
  "$INSTALL_PREFIX/lib/librnp.a" \
  "$INSTALL_PREFIX/include/rnp/rnp.h"; do
  [ -f "$f" ] || { echo "expected output missing: $f" >&2; exit 1; }
done

echo
echo "librnp $RNP_VERSION static built for $NDK_TRIPLE (rust: $RUST_TARGET)"
echo "  install prefix: $INSTALL_PREFIX"
echo "  lib:            $INSTALL_PREFIX/lib/librnp.a"
echo "  header:         $INSTALL_PREFIX/include/rnp/rnp.h"
echo
echo "Set the following env vars before cargo build:"
echo "  RNP_INCLUDE_DIR=$INSTALL_PREFIX/include"
echo "  RNP_LIB_DIR=$INSTALL_PREFIX/lib"
