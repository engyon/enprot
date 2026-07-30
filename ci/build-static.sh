. ci/common.inc.sh

# strip — append so we don't clobber the existing [build] remap-prefix
# in .cargo/config.toml (TODO.completion/12 reproducible builds).
mkdir -p .cargo
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s"]
EOF

. "ci/build-static/pre/$TARGET.sh"

# install cross
cargo install --version "$CROSS_VERSION" cross

# Build with vendored librnp. rnp-src 0.1.2+ builds librnp + Botan
# + json-c + zlib + bzip2 from source inside the container.
cross -vv build --target "$TARGET" --release --features vendored-rnp

. "ci/build-static/post/$TARGET.sh"
