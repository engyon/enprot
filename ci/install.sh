#!/bin/bash -eux
. ci/utils.inc.sh

if [ $(get_os) == "linux" ]; then
  sudo apt update && sudo apt -y install git make g++
  git clone --depth 1 --branch 2.12.1 https://github.com/randombit/botan
  cd botan
  ./configure.py --prefix=/usr --without-documentation
  make -j2
  sudo make install
else
  brew install botan
fi

