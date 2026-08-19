# Docker cross-compile image for x86_64-unknown-linux-musl.
# With vendored-rnp, rnp-src builds Botan + json-c + librnp + zlib +
# bzip2 from source inside the container. Toolchain: zig (see
# musl-common.sh for why — the images' gcc 9.2 musl toolchains
# cannot build Botan 3.12, issue #368).

set -euxo pipefail

ZIG_TARGET=x86_64-linux-musl
# Repo-relative, not $0-relative: GitHub Actions sources build
# scripts through a temp wrapper, so $0 is the wrapper's path.
. ci/build-static/pre/musl-common.sh
