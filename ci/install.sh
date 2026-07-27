#!/bin/bash -eux
. ci/common.inc.sh
. ci/utils.inc.sh

# librnp is required by rnp-rs (OpenPGP signature support). rnp-rs 0.1.6
# expects the latest librnp FFI which lags in distro packages, so build
# from source on every platform.
ci/build-librnp.sh --prefix "$PREFIX"

if [ $(get_os) == "linux" ]; then
  sudo apt update && sudo apt -y install git make g++
  git clone --depth 1 --branch "$BOTAN_VERSION" https://github.com/randombit/botan
  cd botan
  ./configure.py --prefix="$PREFIX" --without-documentation --build-targets=shared \
    --minimized-build --enable-modules=$BOTAN_MODULES --cxxflags=-std=c++20
  make -j2
  sudo make install
else
  brew install botan
fi

