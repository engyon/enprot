#!/bin/bash -eux
# Build librnp from source. rnp-rs 0.1.6 expects the latest librnp FFI
# (rnp_key_get_version, rnp_key_certification_create, etc.) which lag
# behind in distro packages (Ubuntu's librnp-dev, Homebrew's rnp).
#
# Usage:
#   ci/build-librnp.sh [--prefix /usr/local]
#
# Outputs:
#   $PREFIX/include/rnp/rnp.h
#   $PREFIX/lib/librnp.{a,so*,dylib*}
#
# Requires: botan (any 2.14+ or 3.x), json-c, zlib, cmake, git.

PREFIX="/usr/local"
RNP_VERSION="0.18.1"
SRC_DIR="$(mktemp -d)"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --version) RNP_VERSION="$2"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

# Install build deps if missing (Linux only; macOS relies on brew).
if [ "$(uname)" = "Linux" ]; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    cmake libjson-c-dev zlib1g-dev libbz2-dev
fi

git clone --branch "v${RNP_VERSION}" \
  https://github.com/rnpgp/rnp.git "$SRC_DIR/rnp"
cd "$SRC_DIR/rnp"
# libsexpp is a submodule; needed for the cmake build.
git submodule update --init --recursive

# Build librnp via CMake. Force botan backend (librnp also supports
# OpenSSL but botan matches enprot's existing dep).
mkdir -p build
cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DBUILD_TESTING=OFF \
  -DENABLE_DOC=OFF \
  -DCRYPTO_BACKEND=botan \
  -DENABLE_PQC=OFF \
  -DENABLE_CRYPTO_REFRESH=OFF

make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
sudo make install

# Sanity check.
ls "$PREFIX/include/rnp/rnp.h"
echo
echo "librnp $RNP_VERSION installed to $PREFIX"
