# Build the full C dependency stack for macOS ARM64 release.
# Same approach as x86_64-apple-darwin — calls ci/install.sh.

set -euxo pipefail

PREFIX="${PREFIX:-/usr/local}" ./ci/install.sh

export RNP_INCLUDE_DIR="${PREFIX}/include"
export RNP_LIB_DIR="${PREFIX}/lib"
export RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo -L native=${PREFIX}/lib"
