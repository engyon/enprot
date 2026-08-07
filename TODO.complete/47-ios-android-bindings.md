# 47 — iOS + Android mobile bindings

**Priority**: P3
**Status**: specified

## Problem

enprot's FFI (`enprot-ffi`) produces `libenprot.{so,dylib,dll}` —
consumable by Python, Node, Go, Ruby on desktops + servers. Mobile
platforms need different artifacts:

- **iOS**: static `.a` or `.xcframework`, callable from Swift.
- **Android**: `.so` per ABI (arm64-v8a, armeabi-v7a, x86_64), callable
  from Kotlin via JNI.

Mobile bindings would let apps:
- Encrypt user data at rest using EPT format.
- Verify supply-chain provenance of bundled assets.
- Sign user actions with chain anchors.

## Goals

- `libenprot.a` (iOS, arm64 + x86_64 simulator).
- `libenprot.so` per Android ABI (4 ABIs).
- A Swift Package that wraps `libenprot.a` for iOS.
- An Android Archive (`.aar`) wrapping the `.so` files.
- Example iOS app + Android app showing encrypt/decrypt.

## Design

### iOS pipeline

```
enprot-ffi (Rust cdylib)
    ↓ cross-compile
    ├── aarch64-apple-ios         → libenprot_aarch64.a
    ├── aarch64-apple-ios-sim     → libenprot_aarch64_sim.a (simulator)
    └── x86_64-apple-ios          → libenprot_x86_64.a (simulator)
    ↓ lipo (combine to universal)
    libenprot.a
    ↓ wrap
    EnprotKit.xcframework
    ↓ Swift Package
    EnprotKit (Swift API)
```

The xcframework bundles multiple architectures + platforms into one
package that Xcode picks the right slice from at link time.

### Android pipeline

```
enprot-ffi (Rust cdylib)
    ↓ cross-compile (NDK)
    ├── aarch64-linux-android     → libenprot.so (arm64-v8a)
    ├── armv7-linux-androideabi   → libenprot.so (armeabi-v7a)
    ├── x86_64-linux-android      → libenprot.so (x86_64)
    └── i686-linux-android        → libenprot.so (x86)
    ↓ wrap
    enprot.aar (Android Archive)
    ↓ Kotlin bindings
    com.engyon.enprot.Enprot (Kotlin API)
```

The `.aar` is consumable by Gradle; the JNI bindings expose the
`enprot_process(config_json: String): EnprotResult` API.

### Botan on mobile

iOS: build Botan from source via `configure.py --build-targets=static`
(similar to the OHOS path in `ci/build-botan-ohos.sh`).

Android: Botan's Android cross-compile is well-documented; reuse the
NDK clang approach.

### Swift Package shape

```swift
// EnprotKit/Sources/EnprotKit/Enprot.swift
import EnprotC  // C ABI bindings

public struct EnprotConfig: Codable {
    public var word: String
    public var password: String
    public var input: String
    // ...
}

public enum EnprotError: Error {
    case ffiFailure(code: Int32, message: String)
}

public func process(_ config: EnprotConfig) throws -> String {
    let json = try JSONEncoder().encode(config)
    let result = json.withUnsafeBytes { ptr in
        enprot_process(ptr.bindedToCString())
    }
    if result.code != 0 {
        throw EnprotError.ffiFailure(code: result.code, message: result.message)
    }
    return result.output
}
```

### Kotlin bindings shape

```kotlin
// enprot-android/src/main/java/com/engyon/enprot/Enprot.kt
object Enprot {
    init { System.loadLibrary("enprot") }

    external fun process(configJson: String): EnprotResult
}

data class EnprotResult(val code: Int, val message: String, val output: String)
```

## Implementation plan

1. **iOS**: cross-compile `libenprot.a` for the three iOS targets.
   Verify the static lib links cleanly into a Swift project.
2. **iOS**: generate the Swift bindings via `cbindgen` + `swift-bridge`.
3. **iOS**: package as `EnprotKit.xcframework` + Swift Package.
4. **Android**: cross-compile `libenprot.so` for 4 ABIs.
5. **Android**: generate Kotlin bindings via `jnigen` or hand-written JNI.
6. **Android**: package as `enprot.aar`.
7. Examples: a simple iOS app + Android app showing encrypt/decrypt.
8. Documentation: `docs/mobile.md` with setup instructions.

## Test plan

- [ ] `libenprot.a` builds for all 3 iOS targets.
- [ ] `libenprot.so` builds for all 4 Android ABIs.
- [ ] iOS example app runs `enprot encrypt` + `enprot decrypt` end-to-end.
- [ ] Android example app does the same.
- [ ] Swift Package publishes to a public registry.
- [ ] `.aar` publishes to Maven Central.

## Out of scope

- React Native bindings (defer until native iOS+Android are stable).
- Flutter bindings (same).
- WatchOS / tvOS / WearOS (low demand; defer).
- A mobile-first GUI for enprot (separate product).
