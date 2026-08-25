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
# Issue #368 debug instrumentation (temporary): the windows-gnu leg
# stalls inside `Build (unix)` with no output for its full 240-min
# timeout. A background sampler tails the cross container's docker
# logs + top into the job log so the stall point (docker build vs
# cargo vs a specific C make) is visible in the next dispatched
# test build. No-op for other legs / local runs.
if [ "${WGNU_DEBUG:-0}" = "1" ]; then
  # One-shot libclang probe inside the freshly built image: which
  # libclang exists, and can it parse stdbool.h with/without the
  # bindgen args? Settles the "file not found" chain empirically.
  docker run --rm "$PROJECT_NAME/cross-build:$TARGET" sh -c 'echo aW1wb3J0IGN0eXBlcwpmcm9tIGN0eXBlcy51dGlsIGltcG9ydCBmaW5kX2xpYnJhcnkKbGliID0gY3R5cGVzLkNETEwoZmluZF9saWJyYXJ5KCJjbGFuZyIpIG9yICIvdXNyL2xpYi9sbHZtLTE4L2xpYi9jbGFuZy5zby4xIiBpZiBGYWxzZSBlbHNlIGZpbmRfbGlicmFyeSgiY2xhbmciKSBvciAiL3Vzci9saWIvbGx2bS0xOC9saWIvbGliY2xhbmcuc28uMSIpCmxpYi5jbGFuZ19jcmVhdGVJbmRleC5yZXN0eXBlID0gY3R5cGVzLmNfdm9pZF9wCmlkeCA9IGxpYi5jbGFuZ19jcmVhdGVJbmRleCgwLCAwKQpsaWIuY2xhbmdfcGFyc2VUcmFuc2xhdGlvblVuaXQyLnJlc3R5cGUgPSBjdHlwZXMuY19pbnQKbGliLmNsYW5nX2dldE51bURpYWdub3N0aWNzLnJlc3R5cGUgPSBjdHlwZXMuY19pbnQKbGliLmNsYW5nX2dldERpYWdub3N0aWNTcGVsbGluZy5yZXN0eXBlID0gY3R5cGVzLmNfY2hhcl9wCndpdGggb3BlbigiL3RtcC90LmMiLCAidyIpIGFzIGY6CiAgICBmLndyaXRlKCIjaW5jbHVkZSA8c3RkYm9vbC5oPlxuaW50IHg7XG4iKQpmb3IgbmFtZSwgYXJncyBpbiBbCiAgICAoImhvc3QtZGVmYXVsdCIsIFtdKSwKICAgICgibWluZ3ctZnVsbCIsIFsiLS10YXJnZXQ9eDg2XzY0LXc2NC1taW5ndzMyIiwKICAgICAgIi1pc3lzdGVtIiwgIi91c3IvbGliL2xsdm0tMTgvbGliL2NsYW5nLzE4L2luY2x1ZGUiLAogICAgICAiLWlzeXN0ZW0iLCAiL3Vzci9saWIvZ2NjL3g4Nl82NC13NjQtbWluZ3czMi8xMy1wb3NpeC9pbmNsdWRlIiwKICAgICAgIi1pc3lzdGVtIiwgIi91c3IveDg2XzY0LXc2NC1taW5ndzMyL2luY2x1ZGUiXSksCl06CiAgICBlbmNvZGVkID0gW2EuZW5jb2RlKCkgZm9yIGEgaW4gYXJnc10KICAgIGFyZ3YgPSAoY3R5cGVzLmNfY2hhcl9wICogKGxlbihlbmNvZGVkKSArIDEpKSgqZW5jb2RlZCwgTm9uZSkKICAgIHR1ID0gY3R5cGVzLmNfdm9pZF9wKCkKICAgIHJjID0gbGliLmNsYW5nX3BhcnNlVHJhbnNsYXRpb25Vbml0MihpZHgsIGIiL3RtcC90LmMiLCBhcmd2LCBsZW4oZW5jb2RlZCksIE5vbmUsIDAsIDAsIGN0eXBlcy5ieXJlZih0dSkpCiAgICBuID0gbGliLmNsYW5nX2dldE51bURpYWdub3N0aWNzKHR1KQogICAgcHJpbnQoIkJJTkRHRU4tUFJPQkUiLCBuYW1lLCAicmM9IiwgcmMsICJkaWFncz0iLCBuKQogICAgZm9yIGkgaW4gcmFuZ2UobWluKG4sIDIpKToKICAgICAgICBkID0gbGliLmNsYW5nX2dldERpYWdub3N0aWModHUsIGkpCiAgICAgICAgcHJpbnQoIkJJTkRHRU4tUFJPQkUtZGlhZyIsIGxpYi5jbGFuZ19nZXREaWFnbm9zdGljU3BlbGxpbmcoZClbOjEyMF0uZGVjb2RlKGVycm9ycz0icmVwbGFjZSIpKQo= | base64 -d | python3' 2>&1 | sed 's/^/wgnu-probe: /' || true

  (
    end=$((SECONDS + 14400))
    while [ $SECONDS -lt $end ]; do
      sleep 60
      {
        echo "== wgnu-sample t=${SECONDS}s =="
        docker ps --format '{{.ID}} {{.Image}} {{.Status}}' 2>/dev/null
        cid=$(docker ps --filter "ancestor=$PROJECT_NAME/cross-build:$TARGET" -q | head -1)
        if [ -n "$cid" ]; then
          echo "-- docker top --"
          docker top "$cid" -o pid,ppid,etime,cmd 2>/dev/null | tail -n 15
          echo "-- container log tail --"
          docker logs --tail 20 "$cid" 2>&1
        fi
      } || true
    done
  ) &
  WGnuSampler=$!
fi

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

[ -n "${WGnuSampler:-}" ] && kill "$WGnuSampler" 2>/dev/null || true

. "ci/build-static/post/$TARGET.sh"
