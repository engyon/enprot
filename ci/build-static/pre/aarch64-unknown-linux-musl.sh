# Docker cross-compile image for aarch64-unknown-linux-musl.
# Same structure as x86_64 musl — vendored-rnp handles all C deps;
# toolchain via zig (musl-common.sh, issue #368).

set -euxo pipefail

ZIG_TARGET=aarch64-linux-musl
. "$(dirname "$0")/musl-common.sh"
