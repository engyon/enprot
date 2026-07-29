#!/bin/bash -eux
# Cross-compile json-c, bzip2, zlib, and librnp for a musl or mingw
# target. Called inside the Docker image by the pre-build scripts.
#
# Env vars:
#   PREFIX             — install prefix
#   TARGET_CC          — C compiler
#   TARGET_CXX         — C++ compiler
#   TARGET_AR          — archiver
#   CMAKE_SYSTEM_NAME  — Linux (default) or Windows (mingw)

PREFIX="${PREFIX:?PREFIX not set}"
TARGET_CC="${TARGET_CC:?TARGET_CC not set}"
TARGET_CXX="${TARGET_CXX:?TARGET_CXX not set}"
TARGET_AR="${TARGET_AR:?TARGET_AR not set}"
CMAKE_SYSTEM_NAME="${CMAKE_SYSTEM_NAME:-Linux}"
NPROC="${NPROC:-$(nproc 2>/dev/null || echo 2)}"

# CMake toolchain file for cross-compilation.
TOOLCHAIN_FILE="$(mktemp /tmp/toolchain-XXXX.cmake)"
cat > "$TOOLCHAIN_FILE" <<TCM
set(CMAKE_SYSTEM_NAME $CMAKE_SYSTEM_NAME)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER $TARGET_CC)
set(CMAKE_CXX_COMPILER $TARGET_CXX)
set(CMAKE_AR $TARGET_AR)
set(CMAKE_FIND_ROOT_PATH $PREFIX)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
TCM

# ---------- bzip2 ----------
BZIP2_VER=1.0.8
curl -fsSL "https://github.com/libarchive/bzip2/archive/refs/tags/bzip2-$BZIP2_VER.tar.gz" -o /tmp/bzip2.tar.gz
tar -xzf /tmp/bzip2.tar.gz -C /tmp
cd "/tmp/bzip2-$BZIP2_VER"
$TARGET_CC -O2 -c blocksort.c huffman.c crctable.c randtable.c compress.c decompress.c bzlib.c
$TARGET_AR rcs libbz2.a blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o
cp libbz2.a "$PREFIX/lib/"
cp bzlib.h "$PREFIX/include/"
cd -

# ---------- zlib ----------
ZLIB_VER=1.3.1
curl -fsSL "https://github.com/madler/zlib/releases/download/v$ZLIB_VER/zlib-$ZLIB_VER.tar.gz" -o /tmp/zlib.tar.gz
tar -xzf /tmp/zlib.tar.gz -C /tmp
mkdir -p "/tmp/zlib-$ZLIB_VER/build"
cd "/tmp/zlib-$ZLIB_VER/build"
cmake .. -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF
make -j"$NPROC" install
cd -

# ---------- json-c ----------
JSONC_TAG=json-c-0.17-20230812
git clone --depth 1 --branch "$JSONC_TAG" https://github.com/json-c/json-c.git /tmp/json-c
mkdir -p /tmp/json-c/build
cd /tmp/json-c/build
cmake .. -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF
make -j"$NPROC" install
cd -

# ---------- librnp ----------
RNP_VER=0.18.1
git clone --branch "v$RNP_VER" --depth 1 --recursive https://github.com/rnpgp/rnp.git /tmp/rnp
mkdir -p /tmp/rnp/build
cd /tmp/rnp/build
cmake .. -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DENABLE_DOC=OFF \
  -DCRYPTO_BACKEND=botan \
  -DENABLE_PQC=OFF \
  -DENABLE_CRYPTO_REFRESH=OFF \
  -DCMAKE_PREFIX_PATH="$PREFIX"
make -j"$NPROC" install
cd -

ls "$PREFIX/include/rnp/rnp.h"
ls "$PREFIX/lib/librnp.a"
echo "Cross-compiled deps installed to $PREFIX"
