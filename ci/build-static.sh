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
# build. NOTE: --features vendored-rnp is not used yet because rnp-src
# 0.1.1 has a packaging-detection bug (rnpgp/rnp-rs#62). Once fixed,
# vendored will eliminate the need for cross-compiled json-c/librnp.
cross -vv build --target "$TARGET" --release

. "ci/build-static/post/$TARGET.sh"

