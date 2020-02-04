. ci/common.inc.sh

# strip
mkdir .cargo
cat <<EOF > .cargo/config
[target.$TARGET]
rustflags = "-C link-args=-s"
EOF

. "ci/build-static/pre/$TARGET.sh"

# install cross
cargo install --version "$CROSS_VERSION" cross
# build
cross -vv build --target "$TARGET" --release

. "ci/build-static/post/$TARGET.sh"

