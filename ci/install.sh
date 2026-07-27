#!/bin/bash -eux
. ci/common.inc.sh
. ci/utils.inc.sh

if [ $(get_os) == "linux" ]; then
  sudo apt update && sudo apt -y install git make g++ librnp-dev
  git clone --depth 1 --branch "$BOTAN_VERSION" https://github.com/randombit/botan
  cd botan
  ./configure.py --prefix="$PREFIX" --without-documentation --build-targets=shared \
    --minimized-build --enable-modules=$BOTAN_MODULES --cxxflags=-std=c++20
  make -j2
  sudo make install
else
  brew install botan rnp
  # brew install rnp is sometimes keg-only due to conflicts with an
  # older `librnp.a` shipped by another formula. Force-link so the
  # headers and .dylib appear under $(brew --prefix)/include and /lib,
  # which is where rnp-rs's build.rs looks for <rnp/rnp.h>.
  brew link --overwrite rnp || true
fi

