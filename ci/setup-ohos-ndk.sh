#!/usr/bin/env bash
# OHOS NDK setup. Downloads ohos-sdk-public + LLVM-19 from the
# OpenHarmony daily_build API and extracts them.
#
# Reference impl: https://github.com/hqzing/ohos-node/blob/main/build.sh
# Porting guide:  docs/ohos-porting-guide.md
#
# Usage:
#   ci/setup-ohos-ndk.sh --prefix ext/ohos [--ndk-triple aarch64-linux-ohos] \
#                                          [--rust-target aarch64-unknown-linux-ohos]
#
# Outputs (under $PREFIX):
#   ohos-sdk/linux/toolchains/lib/binary-sign-tool
#   ohos-sdk/linux/native/llvm/bin/clang       # if native-*.zip is extracted
#   llvm-19/llvm/bin/aarch64-unknown-linux-ohos-clang++
#   llvm-19/sysroot/aarch64-linux-ohos/usr/... # per-arch sysroot
#
# Environment:
#   NDK_TRIPLE    aarch64-linux-ohos (default) | armv7-linux-ohos | x86_64-linux-ohos
#                  (used for sysroot path + clang --target= flag)
#   RUST_TARGET   aarch64-unknown-linux-ohos (default) | armv7-unknown-linux-ohos | ...
#                  (used for rustup target add + cargo --target; includes "unknown" vendor)

set -euo pipefail

PREFIX=""
NDK_TRIPLE="${NDK_TRIPLE:-aarch64-linux-ohos}"
RUST_TARGET="${RUST_TARGET:-aarch64-unknown-linux-ohos}"

ndk_to_rust_triple() {
  case "$1" in
    aarch64-linux-ohos) echo "aarch64-unknown-linux-ohos";;
    armv7-linux-ohos)   echo "armv7-unknown-linux-ohos";;
    x86_64-linux-ohos)  echo "x86_64-unknown-linux-ohos";;
    *) echo "unknown NDK triple: $1" >&2; exit 1;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)      PREFIX="$2"; shift 2;;
    --ndk-triple)  NDK_TRIPLE="$2"; RUST_TARGET=$(ndk_to_rust_triple "$2"); shift 2;;
    --rust-target) RUST_TARGET="$2"; shift 2;;
    -h|--help) sed -n '2,25p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

[ -n "$PREFIX" ] || { echo "usage: $0 --prefix <dir>" >&2; exit 1; }

mkdir -p "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)"

# Idempotent: if the clang binary exists, assume setup completed.
NDK_CLANGXX="$PREFIX/llvm-19/llvm/bin/${RUST_TARGET//-/_}-clang++"
if [ -x "$NDK_CLANGXX" ]; then
  echo "OHOS NDK already set up at $PREFIX"
  exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need curl; need jq; need unzip; need tar

# --- Download NDK pieces from the OpenHarmony daily_build API -----------
# The CDN resets connections intermittently; --retry-all-errors is required.

query_component() {
  local component="$1"
  curl --retry 5 --retry-delay 5 --retry-all-errors -fsSL \
    'https://dcp.openharmony.cn/api/daily_build/build/list/component' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Content-Type: application/json' \
    --data-raw '{"projectName":"openharmony","branch":"master","pageNum":1,"pageSize":10,"deviceLevel":"","component":"'"${component}"'","type":1,"startTime":"2025080100000000","endTime":"20990101235959","sortType":"","sortField":"","hardwareBoard":"","buildStatus":"success","buildFailReason":"","withDomain":1}'
}

SDK_URL=$(query_component "ohos-sdk-public" | jq -r '.data.list.dataList[0].obsPath')
LLVM_URL=$(query_component "LLVM-19"        | jq -r '.data.list.dataList[0].obsPath')

if [ -z "$SDK_URL" ] || [ "$SDK_URL" = "null" ]; then
  echo "failed to resolve ohos-sdk-public URL" >&2; exit 1;
fi
if [ -z "$LLVM_URL" ] || [ "$LLVM_URL" = "null" ]; then
  echo "failed to resolve LLVM-19 URL" >&2; exit 1;
fi

# --- SDK is a tar.gz containing ohos-sdk/{linux,windows}/<*.zip> --------
echo "Downloading ohos-sdk-public from $SDK_URL"
curl --retry 5 --retry-delay 5 --retry-all-errors -fSL "$SDK_URL" -o "$PREFIX/ohos-sdk.tar.gz"

cd "$PREFIX"
tar -zxf ohos-sdk.tar.gz
rm -f ohos-sdk.tar.gz

# Some releases wrap the SDK dir; normalize to ohos-sdk/.
if [ ! -d "ohos-sdk" ]; then
  SDK_DIR=$(find . -maxdepth 1 -type d -name 'ohos-sdk*' | head -1)
  [ -n "$SDK_DIR" ] || { echo "ohos-sdk dir not found after extraction" >&2; exit 1; }
  [ "$SDK_DIR" = "ohos-sdk" ] || mv "$SDK_DIR" ohos-sdk
fi

# Cleanup: drop Windows SDK + daily-build metadata we don't need.
rm -rf ohos-sdk/windows ohos-sdk/ohos daily_build.log manifest_tag.xml 2>/dev/null || true

# Extract all inner zips in ohos-sdk/linux/. hqzing's reference impl only
# extracts toolchains-*.zip, but extracting native-*.zip too gives us
# ohos.toolchain.cmake (in case a future dep uses CMake) at ~no cost.
cd "$PREFIX/ohos-sdk/linux"
for z in *.zip; do
  [ -e "$z" ] || continue
  echo "  extracting $z"
  unzip -q "$z"
  rm -f "$z"
done

# --- LLVM-19 is a tar.gz containing two inner tarballs -----------------
cd "$PREFIX"
echo "Downloading LLVM-19 from $LLVM_URL"
curl --retry 5 --retry-delay 5 --retry-all-errors -fSL "$LLVM_URL" -o "$PREFIX/llvm-19.tar.gz"

mkdir -p llvm-19
tar -zxf llvm-19.tar.gz -C llvm-19
rm -f llvm-19.tar.gz

# Inside llvm-19/ there are two more tarballs to extract:
#   llvm-linux-x86_64.tar.gz     → llvm-19/llvm/{bin,lib,...}
#   ohos-sysroot.tar.gz          → llvm-19/sysroot/<triple>/usr/...
cd "$PREFIX/llvm-19"
if [ -f llvm-linux-x86_64.tar.gz ]; then
  tar -zxf llvm-linux-x86_64.tar.gz
  rm -f llvm-linux-x86_64.tar.gz
fi
if [ -f ohos-sysroot.tar.gz ]; then
  tar -zxf ohos-sysroot.tar.gz
  rm -f ohos-sysroot.tar.gz
fi

# --- Sanity checks -----------------------------------------------------
if [ ! -x "$NDK_CLANGXX" ]; then
  echo "NDK clang++ not found at $NDK_CLANGXX" >&2
  echo "available clang* in llvm-19/llvm/bin/:" >&2
  ls "$PREFIX/llvm-19/llvm/bin/" | grep -E 'clang' >&2 || true
  exit 1
fi

SYSROOT="$PREFIX/llvm-19/sysroot/$NDK_TRIPLE"
if [ ! -d "$SYSROOT" ]; then
  echo "sysroot for $NDK_TRIPLE not found at $SYSROOT" >&2
  echo "available sysroots:" >&2
  ls "$PREFIX/llvm-19/sysroot/" >&2 || true
  exit 1
fi

echo
echo "OHOS NDK ready at $PREFIX"
echo "  rust target:     $RUST_TARGET"
echo "  ndk triple:      $NDK_TRIPLE"
echo "  clang++ (NDK):   $NDK_CLANGXX"
echo "  sysroot:         $SYSROOT"
echo "  sign tool:       $PREFIX/ohos-sdk/linux/toolchains/lib/binary-sign-tool"
