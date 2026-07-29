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

# Populate the cargo registry on the host so we can apply the
# rnp-src workaround. cross mounts $CARGO_HOME into the container,
# so the patched registry is shared.
cargo fetch --features vendored-rnp 2>/dev/null || true
ci/rnp-src-workaround.sh

# Build with vendored librnp. rnp-src builds librnp + Botan + json-c
# + zlib + bzip2 from source inside the container. Only Botan needs
# to be pre-built for the target arch (via the Docker image).
cross -vv build --target "$TARGET" --release --features vendored-rnp

. "ci/build-static/post/$TARGET.sh"
