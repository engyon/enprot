# Docker cross-compile image for x86_64-pc-windows-gnu (mingw).
# With vendored-rnp, the image only needs build tools. rnp-src
# handles librnp + deps. botan-src auto-detects the mingw toolchain.
#
# Base image: the modern cross-rs registry (ghcr.io), not the
# legacy rustembedded one. The legacy image is ubuntu 20.04 with
# mingw gcc 9, and botan-src 0.31200 (Botan 3.12) refuses to build
# with anything older than gcc 11. The current image is ubuntu
# 24.04 with mingw gcc 12+ (issue #368). Pinned
# to the cross 0.2.5 tag to match CROSS_VERSION — :main moves.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
cat > "$ctx/Dockerfile" <<EOF
FROM ghcr.io/cross-rs/$TARGET:0.2.5

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake git ca-certificates make && \\
    rm -rf /var/lib/apt/lists/*
EOF

docker build -t "$img" "$ctx"
rm -rf "$ctx"

cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"
EOF

# Guarded append: build-static.sh may already have added this
# target's block (TOML forbids duplicate tables — an unconditional
# second append makes every later cargo invocation fail to parse
# the config, killing the cross build).
mkdir -p .cargo
if ! grep -qF "[target.$TARGET]" .cargo/config.toml 2>/dev/null; then
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s"]
EOF
fi
