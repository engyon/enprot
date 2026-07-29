# Build the full C dependency stack for macOS release.
# Reuses ci/install.sh (same script as test CI — DRY).

set -euxo pipefail

PREFIX="${PREFIX:-/usr/local}" ./ci/install.sh

# botan-sys's build.rs uses pkg-config to find botan-3.pc. Without
# PKG_CONFIG_PATH, the probe fails with "not found".
export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig"
export RNP_INCLUDE_DIR="${PREFIX}/include"
export RNP_LIB_DIR="${PREFIX}/lib"
export RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo -L native=${PREFIX}/lib"
