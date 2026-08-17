# Docker cross-compile image for x86_64-pc-windows-gnu (mingw).
# With vendored-rnp, the image only needs build tools. rnp-src
# handles librnp + deps. botan-src auto-detects the mingw toolchain.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
cat > "$ctx/Dockerfile" <<EOF
FROM rustembedded/cross:$TARGET

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
