. ci/common.inc.sh

# strip — append a per-target block so we don't clobber the existing
# [build] remap-prefix in .cargo/config.toml (TODO.completion/12
# reproducible builds). Skip if a pre script already added the block
# for this target (e.g., aarch64-unknown-linux-musl, x86_64-unknown-
# linux-musl, x86_64-pc-windows-gnu) — TOML forbids duplicate keys.
mkdir -p .cargo
if ! grep -qF "[target.$TARGET]" .cargo/config.toml 2>/dev/null; then
  cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s"]
EOF
fi

. "ci/build-static/pre/$TARGET.sh"

# install cross
cargo install --version "$CROSS_VERSION" cross

# Build with vendored librnp. rnp-src 0.1.2+ builds librnp + Botan
# + json-c + zlib + bzip2 from source inside the container.
cross -vv build --target "$TARGET" --release --features vendored-rnp

. "ci/build-static/post/$TARGET.sh"
