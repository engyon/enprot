#!/bin/bash
# Workaround for rnp-src 0.1.1 packaging-detection bug
# (https://github.com/rnpgp/rnp-rs/issues/62).
#
# rnp-src's build.rs checks for Cargo.toml.orig to detect
# `cargo publish --verify`. But Cargo.toml.orig is present in the
# registry cache too, causing the vendored build to be skipped for
# ALL crates.io builds.
#
# This script deletes Cargo.toml.orig from the rnp-src cache so the
# real build runs. Call it AFTER `cargo fetch` (which populates the
# registry) but BEFORE the actual build.

set -euo pipefail

CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
SRC_DIR="${CARGO_HOME}/registry/src"

if [ -d "$SRC_DIR" ]; then
    find "$SRC_DIR" -name "Cargo.toml.orig" -path "*rnp-src*" -delete 2>/dev/null || true
    echo "[rnp-src workaround] Deleted Cargo.toml.orig from rnp-src cache"
else
    echo "[rnp-src workaround] Registry src dir not found: $SRC_DIR"
fi
