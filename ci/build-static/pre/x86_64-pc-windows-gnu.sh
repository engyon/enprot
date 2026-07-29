# Build a Docker image with all cross-compiled deps for Windows (mingw):
#   Botan + json-c + bzip2 + zlib + librnp
# Then configure cross to use it.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

# Create a build context so we can COPY the dep-build script in.
ctx=$(mktemp -d)
cp ci/build-deps-cross.sh "$ctx/"

# For mingw, json-c and librnp need slightly different CMake settings.
# The build-deps-cross.sh script handles Linux/musl; for mingw we
# override the CMake system name via an env var.
cat > "$ctx/Dockerfile" <<EOF
FROM rustembedded/cross:$TARGET-$CROSS_VERSION

ENV PREFIX=$PREFIX
ENV TARGET_CC=$TARGET_CC
ENV TARGET_CXX=$TARGET_CXX
ENV TARGET_AR=$TARGET_AR
ENV CMAKE_SYSTEM_NAME=Windows

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake curl git ca-certificates make && \\
    rm -rf /var/lib/apt/lists/*

# Botan (static, cross-compiled for mingw)
RUN git clone --depth 1 --branch $BOTAN_VERSION https://github.com/randombit/botan /tmp/botan && \\
    cd /tmp/botan && \\
    python3 ./configure.py --prefix=\$PREFIX \\
      --cc=gcc --cc-bin=\$TARGET_CXX --ar-command=\$TARGET_AR \\
      --os=mingw --without-documentation --build-targets=static \\
      --minimized-build --enable-modules=$BOTAN_MODULES && \\
    make -j2 install && \\
    cd / && rm -rf /tmp/botan

# json-c + bzip2 + zlib + librnp (cross-compiled for mingw)
COPY build-deps-cross.sh /tmp/build-deps-cross.sh
RUN chmod +x /tmp/build-deps-cross.sh && CMAKE_SYSTEM_NAME=Windows /tmp/build-deps-cross.sh

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

# Valid cargo config: link-search + strip. Static stdc++ and ssp
# (stack-smashing protector) are needed by mingw Botan.
libstdcxx_path="$(docker run --rm "$img" bash -c "dirname \$($TARGET_CXX --print-file-name libstdc++.a)")"
mkdir -p .cargo
cat <<EOF > .cargo/config
[target.$TARGET]
rustflags = [
  "-C", "link-args=-s",
  "-L", "native=$PREFIX/lib",
  "-L", "native=$libstdcxx_path",
  "-l", "static=stdc++",
  "-l", "static=ssp",
]
EOF
