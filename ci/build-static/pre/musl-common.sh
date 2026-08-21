# Shared setup for the musl cross-compile legs (x86_64 + aarch64).
#
# The vendored C dependency stack (botan-src via rnp-src) needs
# gcc >= 11; every cross image ships musl-cross-make gcc 9.2 and
# Ubuntu packages no newer musl cross toolchain (issue #368).
# Instead of upgrading a compiler we can't get, use zig cc/c++
# (clang-based, bundles musl + libc++) as the C/C++ toolchain:
# one pinned tarball, no compile step, both architectures, and a
# CC/CXX pair that botan-src's configure.py and CMake both
# autodetect as a conventional cross toolchain.
#
# Caller sets ZIG_TARGET (e.g. x86_64-linux-musl) and MUSL_AR
# (the image's musl-cross-make archiver, e.g. x86_64-linux-musl-ar).
#
# rnp-rs's vendored feature ALSO builds a HOST librnp for bindgen
# (see wrappers.sh) — so the compiler env points at OUT_DIR-
# branching tool-* wrappers, not the zig binaries directly, and
# the host side runs the image's native clang/clang++ (a
# clang-family driver, so configure.py's clang-only -W flags and
# -mevex512 parse on both sides).

set -euxo pipefail

ZIG_VERSION=0.13.0

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
mkdir -p "$ctx/tools"

# The zig entry points, written as real files (no printf-escaping
# inside the Dockerfile). `filter` strips rustc's
# --fix-cortex-a53-843419 — rustc (>= the 2026-08-20 stable)
# passes it for aarch64-unknown-linux-musl as BOTH the bare flag
# and compound `-Wl,...` (standalone or inside a comma list);
# zig's ld rejects it outright.
for t in cc c++; do
  cat > "$ctx/tools/musl-$t" <<WRAP
#!/bin/sh
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-cache
export ZIG_GLOBAL_CACHE_DIR

filter() {
  for a in "\$@"; do
    case \$a in
      --fix-cortex-a53-843419) ;;
      -Wl,*)
        segs=\${a#-Wl,}
        out=
        oldifs=\${IFS}
        IFS=,
        set -- \$segs
        for seg in "\$@"; do
          [ "\$seg" = --fix-cortex-a53-843419 ] || out=\${out:+\$out,}\$seg
        done
        IFS=\$oldifs
        [ -n "\$out" ] && printf '%s\n' "-Wl,\$out"
        ;;
      *) printf '%s\n' "\$a" ;;
    esac
  done
}

exec zig $t -target $ZIG_TARGET \$(filter "\$@")
WRAP
  chmod +x "$ctx/tools/musl-$t"
done

cat > "$ctx/Dockerfile" <<EOF
FROM ghcr.io/cross-rs/$TARGET:main

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake git ca-certificates make curl xz-utils gcc g++ clang && \\
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \\
    curl -fsSL https://ziglang.org/download/$ZIG_VERSION/zig-linux-x86_64-$ZIG_VERSION.tar.xz \\
      | tar -xJ -C /opt; \\
    ln -s /opt/zig-linux-x86_64-$ZIG_VERSION/zig /usr/local/bin/zig

COPY tools/ /usr/local/bin/
COPY wrappers/ /usr/local/bin/
EOF

# Repo-relative: on Actions $0 is the runner temp wrapper.
. ci/build-static/pre/wrappers.sh
make_wrappers "$ctx" "$TARGET" musl-cc musl-c++ "$MUSL_AR" musl-c++ clang clang++

docker build -t "$img" "$ctx"
rm -rf "$ctx"

# Zig is the cargo linker (see deploy.yml), and rust must then NOT
# inject its own bundled musl CRT/libc — zig provides musl itself,
# and both together produce duplicate _start/_init/_fini symbols.
# Appending the [target] block here also makes build-static.sh's
# guarded append skip (TOML forbids duplicate tables).
mkdir -p .cargo
if ! grep -qF "[target.$TARGET]" .cargo/config.toml 2>/dev/null; then
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
rustflags = ["-C", "link-self-contained=no", "-C", "link-args=-s"]
EOF
fi

cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"

# Forward the scoped compiler vars into the container (the modern
# cross images don't export host env by default). Deliberately NOT
# plain CC/CXX — host build poisoning (issue #368). The tool-*
# wrappers branch on OUT_DIR, so the TARGET and HOST rnp-src builds
# each get the right compiler; configure.py autodetects the family
# (zig identifies as clang) from the dispatched cc-bin.
[build.env]
passthrough = [
  "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
  "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER",
  "TARGET_CC",
  "TARGET_CXX",
  "TARGET_AR",
  "CC",
  "CXX",
  "AR",
  "HOST_CC",
  "HOST_CXX",
  "HOST_AR",
  "BOTAN_CONFIGURE_CC",
  "BOTAN_CONFIGURE_CC_BIN",
  "BOTAN_CONFIGURE_AR_COMMAND",
  "BOTAN_CONFIGURE_CC_ABI_FLAGS",
  "BOTAN_CONFIGURE_DISABLE_MODULES",
  "BOTAN_CONFIGURE_AMALGAMATION",
]
EOF
