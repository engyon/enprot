#!/bin/bash -eux
. ci/common.inc.sh
. ci/utils.inc.sh

if [ $(get_os) == "linux" ]; then
  sudo apt update && sudo apt -y install git make g++
  git clone --depth 1 --branch "$BOTAN_VERSION" https://github.com/randombit/botan
  cd botan
  ./configure.py --prefix="$PREFIX" --without-documentation --build-targets=shared \
    --minimized-build --enable-modules=$BOTAN_MODULES
  make -j2
  sudo make install
else
  brew install botan
fi

