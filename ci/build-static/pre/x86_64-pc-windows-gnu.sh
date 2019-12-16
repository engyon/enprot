#!/bin/bash -eux
. ci/common.inc.sh

# build a docker image with native deps
img="$PROJECT_NAME/cross-build:$TARGET"
target=${TARGET^^}
docker build -t "$img" -<<EOF
FROM rustembedded/cross:$TARGET-$CROSS_VERSION
ENV CARGO_TARGET_${target//-/_}_LINKER $TARGET_CXX
RUN apt-get -y update && \
    apt-get -y install python && \
    git clone --depth 1 --branch $BOTAN https://github.com/randombit/botan && \
    cd botan && \
    ./configure.py --prefix=$PREFIX --cc=gcc --cc-bin=$TARGET_CXX --ar-command=$TARGET_AR \
      --os=mingw --without-documentation --build-targets=static \
      --minimized-build --enable-modules=$BOTAN_MODULES && \
    make -j2 install && \
    cd .. && \
    rm -rf botan
EOF
cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"
EOF

# override for static linking
libstdcxx_path="$(docker run --rm $img bash -c "dirname \$($TARGET_CXX --print-file-name libstdc++.a)")"
cat <<EOF >> .cargo/config
[target.$TARGET.botan-2]
rustc-link-search = ["native=$PREFIX/lib", "native=$libstdcxx_path"]
rustc-link-lib = ["static=botan-2", "static=stdc++", "static=ssp"]
EOF

