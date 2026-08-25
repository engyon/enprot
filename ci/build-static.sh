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
  docker run --rm "$PROJECT_NAME/cross-build:$TARGET" sh -c 'echo aW1wb3J0IGN0eXBlcwpmcm9tIGN0eXBlcy51dGlsIGltcG9ydCBmaW5kX2xpYnJhcnkKbGliID0gY3R5cGVzLkNETEwoZmluZF9saWJyYXJ5KCJjbGFuZyIpIG9yICIvdXNyL2xpYi9sbHZtLTE4L2xpYi9saWJjbGFuZy5zby4xIikKbGliLmNsYW5nX2NyZWF0ZUluZGV4LnJlc3R5cGUgPSBjdHlwZXMuY192b2lkX3AKaWR4ID0gbGliLmNsYW5nX2NyZWF0ZUluZGV4KDAsIDApCmxpYi5jbGFuZ19wYXJzZVRyYW5zbGF0aW9uVW5pdDIucmVzdHlwZSA9IGN0eXBlcy5jX2ludApsaWIuY2xhbmdfZ2V0TnVtRGlhZ25vc3RpY3MucmVzdHlwZSA9IGN0eXBlcy5jX2ludApsaWIuY2xhbmdfZ2V0RGlhZ25vc3RpY1NwZWxsaW5nLnJlc3R5cGUgPSBjdHlwZXMuY19jaGFyX3AKd2l0aCBvcGVuKCIvdG1wL3QuYyIsICJ3IikgYXMgZjoKICAgIGYud3JpdGUoIiNpbmNsdWRlIDxzdGRib29sLmg+XG5pbnQgeDtcbiIpCmZvciBuYW1lLCBhcmdzIGluIFsKICAgICgiZ251LXRyaXBsZS1vbmx5IiwgWyItLXRhcmdldD14ODZfNjQtcGMtd2luZG93cy1nbnUiXSksCiAgICAoImdudS10cmlwbGUtcGx1cy1vdXJzIiwgWyItLXRhcmdldD14ODZfNjQtcGMtd2luZG93cy1nbnUiLAogICAgICAiLWlzeXN0ZW0iLCAiL3Vzci9saWIvbGx2bS0xOC9saWIvY2xhbmcvMTgvaW5jbHVkZSIsCiAgICAgICItaXN5c3RlbSIsICIvdXNyL2xpYi9nY2MveDg2XzY0LXc2NC1taW5ndzMyLzEzLXBvc2l4L2luY2x1ZGUiLAogICAgICAiLWlzeXN0ZW0iLCAiL3Vzci94ODZfNjQtdzY0LW1pbmd3MzIvaW5jbHVkZSJdKSwKXToKICAgIGVuY29kZWQgPSBbYS5lbmNvZGUoKSBmb3IgYSBpbiBhcmdzXQogICAgYXJndiA9IChjdHlwZXMuY19jaGFyX3AgKiAobGVuKGVuY29kZWQpICsgMSkpKCplbmNvZGVkLCBOb25lKQogICAgdHUgPSBjdHlwZXMuY192b2lkX3AoKQogICAgcmMgPSBsaWIuY2xhbmdfcGFyc2VUcmFuc2xhdGlvblVuaXQyKGlkeCwgYiIvdG1wL3QuYyIsIGFyZ3YsIGxlbihlbmNvZGVkKSwgTm9uZSwgMCwgMCwgY3R5cGVzLmJ5cmVmKHR1KSkKICAgIG4gPSBsaWIuY2xhbmdfZ2V0TnVtRGlhZ25vc3RpY3ModHUpCiAgICBwcmludCgiQklOREdFTi1QUk9CRSIsIG5hbWUsICJyYz0iLCByYywgImRpYWdzPSIsIG4pCiAgICBmb3IgaSBpbiByYW5nZShtaW4obiwgMikpOgogICAgICAgIGQgPSBsaWIuY2xhbmdfZ2V0RGlhZ25vc3RpYyh0dSwgaSkKICAgICAgICBwcmludCgiQklOREdFTi1QUk9CRS1kaWFnIiwgbGliLmNsYW5nX2dldERpYWdub3N0aWNTcGVsbGluZyhkKVs6MTIwXS5kZWNvZGUoZXJyb3JzPSJyZXBsYWNlIikpCg== | base64 -d | python3' 2>&1 | sed 's/^/wgnu-probe: /' || true

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
