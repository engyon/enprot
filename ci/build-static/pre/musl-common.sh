# Shared setup for the musl cross-compile legs (x86_64 + aarch64).
#
# The vendored C dependency stack (botan-src via rnp-src) needs
# gcc >= 11; every cross image ships musl-cross-make gcc 9.2 and
# Ubuntu packages no newer musl cross toolchain (issue #368).
# Instead of upgrading a compiler we can't get, use zig cc/c++
# (clang-based, bundles musl + libc++) as the C/C++ toolchain:
# one pinned tarball, no compile step, both architectures, and a
# CC/CXX pair that botan-src's configure.py and CMake both
# autodetect as a conventional cross toolchain.
#
# Caller sets ZIG_TARGET (e.g. x86_64-linux-musl).

set -euxo pipefail

ZIG_VERSION=0.13.0

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
cat > "$ctx/Dockerfile" <<EOF
FROM ghcr.io/cross-rs/$TARGET:main

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake git ca-certificates make curl xz-utils && \\
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \\
    curl -fsSL https://ziglang.org/download/$ZIG_VERSION/zig-linux-x86_64-$ZIG_VERSION.tar.xz \\
      | tar -xJ -C /opt; \\
    ln -s /opt/zig-linux-x86_64-$ZIG_VERSION/zig /usr/local/bin/zig; \\
    printf '#!/bin/sh\nexec zig cc -target $ZIG_TARGET "\$@"\n' > /usr/local/bin/musl-cc; \\
    printf '#!/bin/sh\nexec zig c++ -target $ZIG_TARGET "\$@"\n' > /usr/local/bin/musl-c++; \\
    chmod +x /usr/local/bin/musl-cc /usr/local/bin/musl-c++
EOF

docker build -t "$img" "$ctx"
rm -rf "$ctx"

cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"

# Forward the scoped compiler vars into the container (the modern
# cross images don't export host env by default). Deliberately NOT
# plain CC/CXX: rnp-src's ureq build-dep builds rustls->ring for the
# HOST, and a cross CC inside that host build corrupts it (issue #368).
[build.env]
passthrough = [
  "TARGET_CC",
  "TARGET_CXX",
  "TARGET_AR",
  "BOTAN_CONFIGURE_CC",
  "BOTAN_CONFIGURE_CC_BIN",
  "BOTAN_CONFIGURE_AR_COMMAND",
]
EOF
