# Docker cross-compile image for x86_64-pc-windows-gnu (mingw).
# With vendored-rnp, the image only needs build tools. rnp-src
# handles librnp + deps. botan-src auto-detects the mingw toolchain.
#
# Base image: the modern cross-rs registry (ghcr.io), not the
# legacy rustembedded one. The legacy image is ubuntu 20.04 with
# mingw gcc 9, and botan-src 0.31200 (Botan 3.12) refuses to build
# with anything older than gcc 11. The current image is ubuntu
# 24.04 with mingw gcc 12+ (issue #368). The :main tag is required:
# the latest version tag (0.2.5) predates cross-rs's ubuntu-24.04
# rebase and still ships mingw gcc 9 — verified by a failed v0.5.52
# deploy on :0.2.5 with the same gcc-11 error. :main moves; the
# trade-off is accepted for the toolchain fix.

set -euxo pipefail

img="$PROJECT_NAME/cross-build:$TARGET"

ctx=$(mktemp -d)
cat > "$ctx/Dockerfile" <<EOF
FROM ghcr.io/cross-rs/$TARGET:main

RUN apt-get -y update && \\
    apt-get -y install --no-install-recommends \\
      python3 cmake git ca-certificates make gcc g++ && \\
    rm -rf /var/lib/apt/lists/*

COPY tools/ /usr/local/bin/
COPY wrappers/ /usr/local/bin/

# cmakew: on --install, tolerate the cross-CLI failure (rnpgp/rnp-rs#72):
# librnp.a + headers install fine, then the CLI rule references an
# executable rnp's CMakeLists never builds when cross-compiling.
# Tolerance is NARROW: real-cmake output must have installed librnp
# AND stderr must match the CMakeRelink CLI miss exactly.
RUN printf '%s\n' \
  '#!/bin/sh' \
  'if [ "\$1" != "--install" ]; then exec /usr/bin/cmake "\$@"; fi' \
  'out=$(/usr/bin/cmake "\$@" 2>/tmp/cmakew.err); st=\$?' \
  '[ \$st -eq 0 ] && { printf "%s" "\$out"; exit 0; }' \
  'if grep -q "CMakeRelink.dir/rnp" /tmp/cmakew.err && printf "%s" "\$out" | grep -q "librnp.a"; then' \
  '  echo "cmakew: tolerating cross-CLI install miss (rnpgp/rnp-rs#72)"; printf "%s" "\$out"; exit 0' \
  'fi' \
  'printf "%s" "\$out"; cat /tmp/cmakew.err >&2; exit \$st' \
  > /usr/local/bin/cmakew && chmod +x /usr/local/bin/cmakew && ln -sf /usr/local/bin/cmakew /usr/local/bin/cmake

# libclang shim: logs clang_parseTranslationUnit2 args to
# /project/shim.log, then forwards to the real libclang. Selected
# via LIBCLANG_PATH=/shim (clang-sys honors the directory).
RUN mkdir -p /shim && printf '%s\n' \
  '#define _GNU_SOURCE' \
  '#include <dlfcn.h>' \
  '#include <stdio.h>' \
  '#include <stddef.h>' \
  'typedef void *(*mkidx_fn)(int, void *);' \
  'mkidx_fn real_mkidx;' \
  'void *clang_createIndex(int e, int x) {' \
  '  if (!real_mkidx) { void *h = dlopen("/usr/lib/llvm-18/lib/libclang.so.1", RTLD_NOW); real_mkidx = (mkidx_fn)dlsym(h, "clang_createIndex"); }' \
  '  return real_mkidx(e, (void *)(size_t)x);' \
  '}' \
  'typedef const char *(*ver_fn)(void);'
  'ver_fn real_ver;'
  'const char *clang_getClangVersion(void) {'
  '  if (!real_ver) { void *h = dlopen("/usr/lib/llvm-18/lib/libclang.so.1", RTLD_NOW); real_ver = (ver_fn)dlsym(h, "clang_getClangVersion"); }'
  '  return real_ver();'
  '}'
  'typedef int (*parse_fn)(void *, const char *, const char *const *, int, void *, int, unsigned, void **);' \
  'parse_fn real_parse;' \
  'int clang_parseTranslationUnit2(void *idx, const char *file, const char *const *args, int n, void *unsaved, int nu, unsigned opts, void **out) {' \
  '  FILE *f = fopen("/project/shim.log", "a");' \
  '  if (f) { fprintf(f, "PARSE file=%s args=%d\n", file, n); for (int i = 0; i < n; i++) fprintf(f, "  [%d] %s\n", i, args[i]); fclose(f); }' \
  '  if (!real_parse) { void *h = dlopen("/usr/lib/llvm-18/lib/libclang.so.1", RTLD_NOW); real_parse = (parse_fn)dlsym(h, "clang_parseTranslationUnit2"); }' \
  '  return real_parse(idx, file, args, n, unsaved, nu, opts, out);' \
  '}' \
  > /shim/shim.c && gcc -shared -fPIC -o /shim/libclang.so.1 /shim/shim.c -ldl
EOF

# mingw filter wrappers: cmake inside rnp-src assumes a Linux build
# (no CMAKE_SYSTEM_NAME is set) and feeds ELF-only flags to the
# compilers — `-rdynamic` on json-c's sample apps is fatal to mingw.
# Same pattern as the musl legs' zig filter: strip what mingw
# cannot parse, exec the real posix-variant toolchain.
mkdir -p "$ctx/tools"
for t in cc c++; do
  real="x86_64-w64-mingw32-gcc-posix"
  [ "$t" = c++ ] && real="x86_64-w64-mingw32-g++-posix"
  cat > "$ctx/tools/mingw-$t" <<MW
#!/bin/sh
args=
out=
prev=
for a in "\$@"; do
  case "\$a" in
    -rdynamic) ;;              # ELF-only; cmake injects it assuming Linux
    *) args="\$args \$a" ;;
  esac
  [ "\$prev" = "-o" ] && out="\$a"
  prev="\$a"
done
# Link mode (an -o target and no -c/-S/-E): Botan's winsock and
# Windows cert-store code (OS-integrated, not a disableable module)
# imports ws2_32/crypt32 — unresolved in rnp's example links and in
# the final enprot.exe link alike. Import libs are inert when
# unused, so append them on every mingw link.
linking=
for a in "\$@"; do
  case "\$a" in
    -c|-S|-E) linking=; break ;;
    -o) linking=1 ;;
  esac
done
[ -n "\$out" ] && [ -n "\$linking" ] && args="\$args -lws2_32 -lcrypt32"
eval "$real" "\$args"
st=\$?
# mingw appends .exe to -o targets; cmake (believing it builds for
# Linux) looks for the extensionless name — CheckTypeSize dies with
# "Cannot copy output executable". Emit both names.
if [ -n "\$out" ] && [ \$st -eq 0 ] && [ ! -e "\$out" ] && [ -e "\$out.exe" ]; then
  cp -f "\$out.exe" "\$out" 2>/dev/null || true
fi
exit \$st
MW
  chmod +x "$ctx/tools/mingw-$t"
done

# Repo-relative: on Actions $0 is the runner temp wrapper.
. ci/build-static/pre/wrappers.sh
# OUT_DIR-branching dispatch: target build => mingw, host build =>
# native gcc. rnp-rs's vendored feature builds librnp BOTH ways
# (regular dep for the binary, build dep for bindgen) and both
# inherit the same env — a static mingw assignment poisons the
# host copy (issue #368).
make_wrappers "$ctx" "$TARGET" \
  mingw-cc mingw-c++ \
  x86_64-w64-mingw32-gcc-ar-posix mingw-c++

# Botan's --os=windows build archives as botan-3.lib, but both
# consumers want libbotan-3.a: rustc's -l static=botan-3 on
# pc-windows-gnu, and rnp-src (whose lib-name check is host-
# conditional — the script runs on Linux, so it looks for the
# unix name). Replace tool-ar with a version that also emits the
# unix name whenever it archives botan-3.lib.
cat > "$ctx/wrappers/tool-ar" <<WAR
#!/bin/sh
case "\$OUT_DIR" in
  */x86_64-pc-windows-gnu/*)
    x86_64-w64-mingw32-gcc-ar-posix "\$@"
    st=\$?
    # `ar crs <lib> <obj>...` puts the ARCHIVE first, objects after —
    # the previous last-arg match never fired (last = the .obj), so
    # libbotan-3.a was never produced and rnp-src's lib-name check
    # panicked. Scan every argument instead.
    for a in "\$@"; do
      case \$a in
        */botan-3.lib) cp -f "\$a" "\${a%botan-3.lib}libbotan-3.a" 2>/dev/null || true ;;
      esac
    done
    exit \$st
    ;;
  *) exec /usr/bin/ar "\$@" ;;
esac
WAR
chmod +x "$ctx/wrappers/tool-ar"

docker build -t "$img" "$ctx"
rm -rf "$ctx"

# botan-src's configure.py aborts for --os=windows when the host
# python is posix: the windows os-info file's install_root
# 'c:\\Botan' fails os.path.isabs ("The installation root must be
# an absolute path"), so the TARGET configure can never succeed
# inside a Linux cross container. botan-src honors BOTAN_SRC_TARBALL
# (checksum-free); repack the vendored tarball with a posix-absolute
# install root and hand that over instead. Version comes from
# Cargo.lock so it cannot drift from the resolved botan-src.
# rnp-src pins =0.31200; the lock also carries botan-sys's older
# optional botan-src — take the LAST entry (rnp-src's pin).
botan_src_ver=$(sed -n '/^name = "botan-src"$/{n;p;}' Cargo.lock | tail -n1 | cut -d'"' -f2)
# static.crates.io is the canonical CDN; the api/v1 download
# endpoint 403s intermittently (rate limiting).
curl -fsSL --retry 5 --retry-delay 3 \
  "https://static.crates.io/crates/botan-src/botan-src-$botan_src_ver.crate" \
  -o botan-src.crate
pt=$(mktemp -d)
tar -xzf botan-src.crate -C "$pt"
# Published crates extract to <name>-<version>/ (cargo package's
# local layout uses package/ instead).
inner=$(ls "$pt"/botan-src-*/vendor/Botan-*.tar.xz)
tar -xJf "$inner" -C "$pt"
botan_dir=$(basename "$inner" .tar.xz)
sed -i "s|^install_root .*|install_root /c/Botan|" \
  "$pt/$botan_dir/src/build-data/os/windows.txt"
tar -cJf botan-windows-posix-install-root.tar.xz -C "$pt" "$botan_dir"

# cross mounts the project root at /project in the container.
export BOTAN_SRC_TARBALL=/project/botan-windows-posix-install-root.tar.xz

cat <<EOF > Cross.toml
[target.$TARGET]
image = "$img"

# Explicit env passthrough: cross only forwards a known set of
# variables to the container by default (issue #368). Plain
# CC/CXX/AR is needed for rnp-src's CMake deps; HOST_CC/HOST_CXX
# shield the cc-crate host builds (rustls->ring via rnp-src's ureq
# build-dep), and the tool-* wrappers branch on OUT_DIR for the
# host librnp copy.
[build.env]
passthrough = [
  "TARGET_CC",
  "TARGET_CXX",
  "TARGET_AR",
  "CC",
  "CXX",
  "AR",
  "HOST_CC",
  "HOST_CXX",
  "HOST_AR",
  "BINDGEN_EXTRA_CLANG_ARGS",
  "BOTAN_CONFIGURE_CC",
  "BOTAN_CONFIGURE_CC_BIN",
  "BOTAN_CONFIGURE_AR_COMMAND",
  "BOTAN_CONFIGURE_DISABLE_MODULES",
  "BOTAN_CONFIGURE_AMALGAMATION",
  "BOTAN_SRC_TARBALL",
]
EOF

# cross-rs word-splits passthrough env values, so multi-flag
# BINDGEN_EXTRA_CLANG_ARGS never arrives intact. cargo's [env]
# table sets build-script env inside the container directly — no
# passthrough involved.
mkdir -p .cargo
if ! grep -qF "[env]" .cargo/config.toml 2>/dev/null; then
cat <<EOF >> .cargo/config.toml
[env]
LIBCLANG_PATH = "/shim"
BINDGEN_EXTRA_CLANG_ARGS = "--target=x86_64-w64-mingw32 -isystem /usr/lib/llvm-18/lib/clang/18/include -isystem /usr/lib/gcc/x86_64-w64-mingw32/13-posix/include -isystem /usr/x86_64-w64-mingw32/include"
RUST_LOG = { value = "bindgen=debug", force = true }
EOF
fi

# Guarded append: build-static.sh may already have added this
# target's block (TOML forbids duplicate tables — an unconditional
# second append makes every later cargo invocation fail to parse
# the config, killing the cross build).
mkdir -p .cargo
if ! grep -qF "[target.$TARGET]" .cargo/config.toml 2>/dev/null; then
cat <<EOF >> .cargo/config.toml
[target.$TARGET]
# ws2_32/crypt32: Botan's winsock + Windows cert-store imports; the
# final link goes through RUSTC_LINKER directly, bypassing the
# mingw wrappers.
rustflags = ["-C", "link-args=-s", "-C", "link-args=-lws2_32", "-C", "link-args=-lcrypt32"]
EOF
fi
