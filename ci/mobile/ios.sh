#!/bin/bash
# iOS xcframework build (TODO.complete/47). REQUIRES: Xcode + iOS SDK
# + lipo. Run from the repo root. Fails fast with a clear message if
# the toolchain isn't present so CI can skip this leg gracefully.
#
# Pipeline: enprot-ffi (Rust cdylib + staticlib)
#   → cargo build --target aarch64-apple-ios [+ aarch64-apple-ios-sim]
#   → lipo -create (combine to a universal .a)
#   → xcodebuild -create-xcframework → EnprotKit.xcframework

set -euo pipefail

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "error: Xcode not installed (need xcodebuild + iOS SDK)" >&2
  echo "  install Xcode, accept the license, and install the iOS component" >&2
  exit 1
fi
if ! command -v cargo-lipo >/dev/null 2>&1; then
  echo "note: cargo-lipo not found; using manual lipo(1) instead"
fi

TARGETS_DEVICE="aarch64-apple-ios"
TARGETS_SIM="aarch64-apple-ios-sim x86_64-apple-ios"

echo "Building enprot-ffi for iOS targets:"
for t in $TARGETS_DEVICE $TARGETS_SIM; do
  if ! rustup target list --installed | grep -q "^$t$"; then
    echo "  installing $t"
    rustup target add "$t"
  fi
  echo "  cargo build --release --target $t -p enprot-ffi"
  cargo build --release --target "$t" -p enprot-ffi
done

OUT=dist/ios
mkdir -p "$OUT"

# lipo the simulator slices into one universal .a
lipo -create \
  target/aarch64-apple-ios-sim/release/libenprot.a \
  target/x86_64-apple-ios/release/libenprot.a \
  -output "$OUT/libenprot_sim.a" 2>/dev/null || {
    echo "warning: lipo failed; simulator slices may not both exist"
    cp target/aarch64-apple-ios-sim/release/libenprot.a "$OUT/libenprot_sim.a"
  }

# the device slice is arm64-only (no lipo needed)
cp target/aarch64-apple-ios/release/libenprot.a "$OUT/libenprot_device.a"

# xcframework
rm -rf "$OUT/EnprotKit.xcframework"
xcodebuild -create-xcframework \
  -library "$OUT/libenprot_device.a" \
  -library "$OUT/libenprot_sim.a" \
  -output "$OUT/EnprotKit.xcframework"

echo ""
echo "Built: $OUT/EnprotKit.xcframework"
echo "  (device: arm64; simulator: arm64 + x86_64)"
echo "Next: wrap with a Swift Package (see TODO.complete/47)."
