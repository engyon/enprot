#!/bin/sh
# Preflight: print the container's build reality so a failing leg
# diagnoses itself in the log instead of costing a debug dispatch.
# Baked into the cross images by the per-target pre scripts and run
# right after `docker build`; the output block is diffable across
# runs — image drift (gcc bumps, libclang swaps, moving :main tags)
# shows up here before it bites the build.
set -eu

say() { echo "[preflight] $*"; }

# --- mount reality -------------------------------------------------
# cross mounts the project at /project for ordinary workspaces and at
# the host-absolute path when path dependencies exist. Both spellings
# being visible is normal; neither is a bug — but which one exists
# decides what $BOTAN_SRC_TARBALL must point at.
if [ -d /project ]; then
    say "mount: /project (no-path-deps shape)"
fi
if [ "${PWD:-}" != "/project" ] && [ -d "${PWD:-/nonexistent}" ]; then
    say "mount: also cwd=$PWD"
fi

# --- libclang identity ---------------------------------------------
# Which libclang a bindgen would dlopen, and whether its resource
# headers (the freestanding C set) actually resolve.
first_libclang() {
    ldconfig -p 2>/dev/null | awk '/libclang/ {print $NF; exit}' || true
}
lc="$(first_libclang)"
if [ -n "$lc" ]; then
    say "libclang: $lc"
else
    found=""
    for d in /usr/lib/llvm-*/lib /usr/lib/x86_64-linux-gnu; do
        for f in "$d"/libclang-*.so*; do
            [ -e "$f" ] || continue
            say "libclang: $f"
            found=1
            break 2
        done
    done
    [ -n "$found" ] || say "libclang: NOT FOUND"
fi
for r in /usr/lib/llvm-*/lib/clang/*/include/stdbool.h; do
    [ -e "$r" ] && say "resource headers: $r"
done

# --- toolchain ------------------------------------------------------
for t in gcc g++ clang clang-18 x86_64-w64-mingw32-gcc-posix zig cmake; do
    p="$(command -v "$t" 2>/dev/null || true)"
    [ -n "$p" ] || continue
    v="$("$t" --version 2>/dev/null | head -n1 || echo '?')"
    say "tool: $t = $v"
done

# --- critical headers -----------------------------------------------
# The freestanding C set bindgen needs; absence predicts
# 'stdbool.h file not found' before the build reaches it.
for h in stdbool.h stddef.h; do
    where=""
    for d in /usr/lib/llvm-*/lib/clang/*/include \
             /usr/lib/gcc/x86_64-w64-mingw32/*/include \
             /usr/lib/gcc/x86_64-linux-gnu/*/include \
             /usr/x86_64-w64-mingw32/include; do
        [ -e "$d/$h" ] && where="$where $d"
    done
    if [ -n "$where" ]; then
        say "header $h: ok ($where )"
    else
        say "header $h: NOT FOUND"
    fi
done

say "preflight complete"
