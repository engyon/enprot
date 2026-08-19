# Docker cross-compile image for aarch64-unknown-linux-musl.
# Same structure as x86_64 musl — vendored-rnp handles all C deps;
# toolchain via zig (musl-common.sh, issue #368).

set -euxo pipefail

ZIG_TARGET=aarch64-linux-musl
MUSL_AR=aarch64-linux-musl-ar
# Repo-relative, not $0-relative: GitHub Actions sources build
# scripts through a temp wrapper, so $0 is the wrapper's path.
. ci/build-static/pre/musl-common.sh
