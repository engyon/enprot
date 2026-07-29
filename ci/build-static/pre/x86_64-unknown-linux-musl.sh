# Docker cross-compile image for x86_64-unknown-linux-musl.
# With vendored-rnp, rnp-src builds Botan + json-c + librnp + zlib +
# bzip2 from source inside the container. The image only needs build
# tools + the cross-compile toolchain.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
target_unix=$(echo "$TARGET" | tr 'a-z-' 'A-Z_')

cat > "$ctx/Dockerfile" <<EOF
FROM rustembedded/cross:$TARGET

# Build tools for rnp-src's CMake-based build of librnp + deps.
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

# Linker wrapper for musl static CRT piecing (rust-lang/rust #36710).
# cross mounts the project root into the container, so ./linker is
# available at runtime.
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

# Strip flag appended to existing .cargo/config.toml.
mkdir -p .cargo
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s"]
EOF
