# Docker cross-compile image for aarch64-unknown-linux-musl.
# Same structure as x86_64 — vendored-rnp handles all C deps.

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
