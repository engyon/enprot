. ci/common.inc.sh

# Source the pre script FIRST: musl-common.sh writes its own richer
# [target.$TARGET] rustflags block (link-self-contained=no for the
# zig linker) and relies on this append's guard to stay away. The
# generic strip-only block below is the fallback for legs whose
# pre script writes nothing.
. "ci/build-static/pre/$TARGET.sh"

mkdir -p .cargo
if ! grep -qF "[target.$TARGET]" .cargo/config.toml 2>/dev/null; then
  cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-args=-s"]
EOF
fi

# install cross
cargo install --version "$CROSS_VERSION" cross

# NOTE: no `rm -rf target` here. It was added for hermeticity
# (issue #368: cross-arch artifacts poisoning the shared /target
# volume), but the build-script outputs under target/ are now the
# deploy cache — wiping them rebuilds ~90 min of C stack per leg.
# Hermeticity comes from the cache KEY instead: it is strictly
# per-(target, Cargo.lock, rustc, ci files), so a leg can never
# restore another leg's or a stale configuration's artifacts.

# Build with vendored librnp. rnp-src 0.1.2+ builds librnp + Botan
# + json-c + zlib + bzip2 from source inside the container.
#
# -vv traces every subcommand but has been observed to exit 101
# with the underlying cargo error swallowed (issue #368: the
# windows-gnu leg dies 250ms after rnp-src's build script succeeds,
# printing nothing between its cargo: directives and cross's
# rustup diagnostic). On failure, re-run WITHOUT -vv — the plain
# invocation surfaces the real cargo error — and dump the assembled
# config for the log.
# botan/vendored is passed HERE (not folded into the vendored-rnp
# feature): the containers have no system Botan, and on unix the
# botan crate otherwise defaults to pkg-config and its build script
# dies. Tests use system Botan and must not get the vendored copy.
# windows-gnu needs it too: botan-sys compiles INDEPENDENTLY of
# rnp-src (no ordering guarantee), and its rustc fails fast on -l
# static=botan-3 with no search path. The "share rnp-src's Botan"
# design has no transport for the link path, so this leg builds
# Botan twice — the second one lands in the OUT_DIR cache like
# every other C artifact.
case "$TARGET" in
  *-linux-musl|*-windows-gnu) features="vendored-rnp,botan/vendored" ;;
  *)                          features="vendored-rnp" ;;
esac
if ! cross -vv build --target "$TARGET" --release --features "$features"; then
  echo "=== build failed; dumping assembled config and retrying without -vv ==="
  echo "--- .cargo/config.toml ---"; cat .cargo/config.toml || true
  echo "--- Cross.toml ---"; cat Cross.toml || true
  echo "--- container env/toolchain ---"
  docker run --rm "$PROJECT_NAME/cross-build:$TARGET" \
    sh -c 'echo CC=$CC CXX=$CXX; command -v x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc-posix x86_64-w64-mingw32-g++-posix || true' || true
  cross build --target "$TARGET" --release --features "$features" 2>&1 | tail -n 120
  exit 1
fi

. "ci/build-static/post/$TARGET.sh"
