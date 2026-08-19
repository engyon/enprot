#!/bin/bash -eux
. ci/common.inc.sh
. ci/utils.inc.sh

# Build Botan FIRST — librnp depends on it.
if [ $(get_os) == "linux" ]; then
  # Fail fast + retry: the runners' azure apt mirrors occasionally
  # stall silently (2026-08-19: a 30-minute hang ate every ubuntu
  # job's timeout). Default apt has no network timeout at all.
  # The runners' primary mirror (azure.archive.ubuntu.com) stalls
  # silently below apt's HTTP timeout (2026-08-19: three separate
  # 30-minute job timeouts); archive.ubuntu.com — already in the
  # same sources list — responds fine. Point the list at it.
  sudo sed -i 's|azure.archive.ubuntu.com|archive.ubuntu.com|' \
    /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
  APT_NET="-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=5"
  sudo apt $APT_NET update && sudo apt $APT_NET -y install git make g++
  git clone --depth 1 --branch "$BOTAN_VERSION" https://github.com/randombit/botan
  cd botan
  ./configure.py --prefix="$PREFIX" --without-documentation --build-targets=shared \
    --minimized-build --enable-modules=$BOTAN_MODULES --cxxflags=-std=c++20
  make -j2
  sudo make install
  cd ..
else
  brew install botan
fi

# librnp is required by rnp-rs (OpenPGP signature support). rnp-rs 0.1.6
# expects the latest librnp FFI which lags in distro packages, so build
# from source on every platform.
ci/build-librnp.sh --prefix "$PREFIX"

