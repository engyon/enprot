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

# Hermetic build: no artifacts may survive from any earlier
# invocation (issue #368). The windows-gnu leg linked ring rlib
# members containing Linux ELF objects into a PE binary — stale
# host-arch artifacts in the shared /target volume. A clean target
# also makes each release build reproducible from zero.
rm -rf target

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
if ! cross -vv build --target "$TARGET" --release --features vendored-rnp; then
  echo "=== build failed; dumping assembled config and retrying without -vv ==="
  echo "--- .cargo/config.toml ---"; cat .cargo/config.toml || true
  echo "--- Cross.toml ---"; cat Cross.toml || true
  echo "--- container env/toolchain ---"
  docker run --rm "$PROJECT_NAME/cross-build:$TARGET" \
    sh -c 'echo CC=$CC CXX=$CXX; command -v x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc-posix x86_64-w64-mingw32-g++-posix || true' || true
  cross build --target "$TARGET" --release --features vendored-rnp 2>&1 | tail -n 120
  exit 1
fi

. "ci/build-static/post/$TARGET.sh"
