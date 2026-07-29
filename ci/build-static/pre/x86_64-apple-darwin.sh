# Build the full C dependency stack for macOS release.
# Reuses ci/install.sh (same script as test CI — DRY).
# install.sh builds Botan + json-c + librnp and sets RNP_INCLUDE_DIR /
# RNP_LIB_DIR via the environment.

set -euxo pipefail

# install.sh expects PREFIX and BOTAN_VERSION in the env (deploy.yml
# provides them). It calls ci/build-librnp.sh internally.
PREFIX="${PREFIX:-/usr/local}" ./ci/install.sh

# install.sh writes GITHUB_ENV entries in CI; here we just keep the
# exports for the current shell. The deploy build (cargo build) picks
# them up.
export RNP_INCLUDE_DIR="${PREFIX}/include"
export RNP_LIB_DIR="${PREFIX}/lib"
export RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo -L native=${PREFIX}/lib"
