# Build a Docker image with all cross-compiled deps:
#   Botan + json-c + bzip2 + zlib + librnp
# Then configure cross to use it.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

# Create a build context so we can COPY the dep-build script in.
ctx=$(mktemp -d)
cp ci/build-deps-cross.sh "$ctx/"
cat > "$ctx/Dockerfile" <<EOF
FROM rustembedded/cross:$TARGET-$CROSS_VERSION

ENV PREFIX=$PREFIX
ENV TARGET_CC=$TARGET_CC
ENV TARGET_CXX=$TARGET_CXX
ENV TARGET_AR=$TARGET_AR

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake curl git ca-certificates make && \\
    rm -rf /var/lib/apt/lists/*

# Botan (static, cross-compiled)
RUN git clone --depth 1 --branch $BOTAN_VERSION https://github.com/randombit/botan /tmp/botan && \\
    cd /tmp/botan && \\
    python3 ./configure.py --prefix=\$PREFIX \\
      --cc-bin=\$TARGET_CXX --ar-command=\$TARGET_AR \\
      --without-documentation --build-targets=static --minimized-build \\
      --enable-modules=$BOTAN_MODULES && \\
    make -j2 install && \\
    cd / && rm -rf /tmp/botan

# json-c + bzip2 + zlib + librnp (cross-compiled)
COPY build-deps-cross.sh /tmp/build-deps-cross.sh
RUN chmod +x /tmp/build-deps-cross.sh && /tmp/build-deps-cross.sh

ENV RNP_INCLUDE_DIR=\$PREFIX/include
ENV RNP_LIB_DIR=\$PREFIX/lib
ENV PKG_CONFIG_PATH=\$PREFIX/lib/pkgconfig
ENV ENPRO_STATIC_LINK=1
EOF

docker build -t "$img" "$ctx"
rm -rf "$ctx"

cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"
EOF

# Linker wrapper — see rust issue #36710 (static CRT piecing).
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
"$TARGET_CXX" "\${args[@]}"
EOF
chmod +x linker

# Valid cargo config: link-search + strip. The old [target.X.botan-3]
# subtable syntax was invalid and silently ignored by Cargo. Append to
# .cargo/config.toml (which is tracked) so the [build] remap-prefix
# flag from TODO.completion/12 is preserved alongside the target-
# specific link directives.
mkdir -p .cargo
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s", "-L", "native=$PREFIX/lib"]
EOF
