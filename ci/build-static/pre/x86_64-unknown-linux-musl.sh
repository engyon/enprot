#!/bin/bash -eux
. ci/common.inc.sh

# build a docker image with native deps
img="$PROJECT_NAME/cross-build:$TARGET"
target=${TARGET^^}
docker build -t "$img" -<<EOF
FROM rustembedded/cross:$TARGET-$CROSS_VERSION
ENV CARGO_TARGET_${target//-/_}_LINKER ./linker
RUN apt-get -y update && \
    apt-get -y install python && \
    git clone --depth 1 --branch $BOTAN https://github.com/randombit/botan && \
    cd botan && \
    ./configure.py --prefix=$PREFIX --cc-bin=$TARGET_CXX --ar-command=$TARGET_AR \
    --without-documentation --build-targets=static --minimized-build \
    --enable-modules=$BOTAN_MODULES && \
    make -j2 install && \
    cd .. && \
    rm -rf botan
EOF
cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"
EOF

# linker wrapper script - see rust issue #36710
cat <<EOF > linker
#!/bin/bash -eux
args=()
for arg in "\$@"; do
  if [[ \$arg = *"Bdynamic"* ]]; then
    :
  elif [[ \$arg = *"crti.o"* ]]; then
    args+=("\$arg" "\$($TARGET_CXX --print-file-name crtbeginT.o)" "-Bstatic")
  elif [[ \$arg = *"crtn.o"* ]]; then
    args+=("-lgcc" "-lgcc_eh" "-lc" "\$($TARGET_CXX --print-file-name crtend.o)" "\$arg")
  else
    args+=("\$arg")
  fi
done
# shell out to the real linker
"$TARGET_CXX" "\${args[@]}"
EOF
chmod +x linker

# override for static linking
cat <<EOF >> .cargo/config
[target.$TARGET.botan-2]
rustc-link-search = ["native=$PREFIX/lib"]
rustc-link-lib = ["static=botan-2", "static=stdc++"]
EOF

