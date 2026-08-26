#!/bin/bash
# Android .aar build (TODO.complete/47). REQUIRES: Android NDK (r26+),
# aapt2, gradle. Run from the repo root. Fails fast if NDK is absent.
#
# Pipeline: enprot-ffi (Rust cdylib)
#   → cargo build --target <abi> for each of 4 ABIs
#   → package into enprot.aar (Android Archive)

set -euo pipefail

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "error: ANDROID_NDK_HOME not set" >&2
  echo "  install the Android NDK (r26+) and set ANDROID_NDK_HOME" >&2
  echo "  https://developer.android.com/ndk/downloads" >&2
  exit 1
fi

ABIS="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android"

echo "Building enprot-ffi for Android ABIs:"
for t in $ABIS; do
  if ! rustup target list --installed | grep -q "^$t$"; then
    echo "  installing $t"
    rustup target add "$t"
  fi
  # Linker: NDK's clang wrapper for each ABI
  case "$t" in
    aarch64-linux-android)         LINKER=aarch64-linux-android24-clang ;;
    armv7-linux-androideabi)       LINKER=armv7a-linux-androideabi24-clang ;;
    x86_64-linux-android)          LINKER=x86_64-linux-android24-clang ;;
    i686-linux-android)            LINKER=i686-linux-android24-clang ;;
  esac
  export "CARGO_TARGET_${t//-/_}_LINKER=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/$LINKER"
  echo "  cargo build --release --target $t -p enprot-ffi"
  cargo build --release --target "$t" -p enprot-ffi
done

OUT=dist/android
mkdir -p "$OUT"/{jni/{arm64-v8a,armeabi-v7a,x86_64,x86},}

cp target/aarch64-linux-android/release/libenprot.so "$OUT/jni/arm64-v8a/"
cp target/armv7-linux-androideabi/release/libenprot.so "$OUT/jni/armeabi-v7a/"
cp target/x86_64-linux-android/release/libenprot.so "$OUT/jni/x86_64/"
cp target/i686-linux-android/release/libenprot.so "$OUT/jni/x86/"

if ! command -v aapt2 >/dev/null 2>&1; then
  echo "warning: aapt2 not found; .so files staged but not packaged into an .aar" >&2
  echo "  install Android SDK build-tools for aapt2, then re-run to produce enprot.aar"
  echo "Built: $OUT/jni/ (4 ABI .so files)"
  exit 0
fi

# Minimal .aar: just the jni/ tree. A full .aar adds the Kotlin
# wrapper (src/main/kotlin/Enprot.kt) and an AndroidManifest.xml.
cd "$OUT"
zip -r enprot.aar jni/
echo ""
echo "Built: $PWD/enprot.aar"
echo "Next: add the Kotlin JNI wrapper (see TODO.complete/47)."
