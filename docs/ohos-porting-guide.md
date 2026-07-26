# Porting C libraries and Rust crates to OHOS (OpenHarmony)

A practical guide distilled from shipping `libpng-ruby` 1.6.58.6 for
`aarch64-linux-ohos`, adapted for enprot. Covers the NDK architecture,
the workarounds the official docs leave out, and how to wire it all
into CI.

Source gist: <https://gist.github.com/ronaldtse/78b6b610cfa00ead8fb3b8f935afaa3b>

## Why OHOS needs special treatment

OHOS (OpenHarmony / Huawei HarmonyOS) is musl-based arm64. **Naively
reusing `aarch64-linux-musl` bytes does not work** — even though the
dynamic linker path matches (`/lib/ld-musl-aarch64.so.1`), the ABIs
differ in subtle ways:

- musl symbol versions (Alpine carries patches OHOS doesn't, and vice versa)
- Default symbol visibility (`-fvisibility=hidden` defaults differ)
- TLS / pthread struct layout
- OHOS's non-standard zlib SONAME (`libshared_libz.z.so`, not `libz.so`)
- OHOS requires code signing on `.so` files for runtime loading on production devices

You need the official OHOS NDK.

## Architecture: what to download

The NDK has two pieces, both from the OpenHarmony `daily_build` API:

```sh
query_component() {
  component=$1
  curl --retry 5 --retry-delay 5 --retry-all-errors -fsSL \
    'https://dcp.openharmony.cn/api/daily_build/build/list/component' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Content-Type: application/json' \
    --data-raw '{"projectName":"openharmony","branch":"master","pageNum":1,"pageSize":10,"deviceLevel":"","component":"'"${component}"'","type":1,"startTime":"2025080100000000","endTime":"20990101235959","sortType":"","sortField":"","hardwareBoard":"","buildStatus":"success","buildFailReason":"","withDomain":1}'
}

sdk_url=$(query_component "ohos-sdk-public" | jq -r '.data.list.dataList[0].obsPath')
llvm_url=$(query_component "LLVM-19"       | jq -r '.data.list.dataList[0].obsPath')
```

- **`ohos-sdk-public`** (~3.2 GB): contains `toolchains/lib/binary-sign-tool`,
  and after you unzip `native-*.zip`, also `native/build/cmake/ohos.toolchain.cmake`
  + `native/llvm/bin/clang`.
- **`LLVM-19`** (~670 MB): contains `llvm-linux-x86_64.tar.gz` (the clang
  itself — yes, x86_64 ELF, even for arm64 target) + `ohos-sysroot.tar.gz`
  (the per-arch sysroots).

**Critical**: extract ALL the zips in `ohos-sdk/linux/`, not just
`toolchains-*.zip`:

```sh
cd "$PREFIX/ohos-sdk/linux"
for z in *.zip; do
  unzip -q "$z"
  rm -f "$z"
done
```

If you only unzip `toolchains-*.zip` (like `ohos-node` does — they don't
need CMake), you'll be missing `native/build/cmake/ohos.toolchain.cmake`.

## The two-sysroots problem

This is the part that cost 8 CI iterations in the reference impl. The
OHOS NDK ships TWO sysroots with **different layouts**, and the
toolchain expects a specific one:

| Location | Layout | Has |
| --- | --- | --- |
| `ohos-sdk/linux/native/sysroot/usr/include/` | MULTIARCH: `usr/include/<arch>/bits/...` | `limits.h` but `bits/alltypes.h` at `usr/include/aarch64-linux-ohos/bits/alltypes.h` |
| `llvm-19/sysroot/aarch64-linux-ohos/usr/include/` | PER-ARCH: `<arch>/usr/include/bits/...` | `bits/alltypes.h` directly under `usr/include/bits/` |

The `ohos.toolchain.cmake` resolves `CMAKE_SYSROOT` relative to its
own location → it picks `ohos-sdk/linux/native/sysroot/` (multiarch).
Headers fail to resolve.

**Fix**: replace the SDK's multiarch sysroot with a **relative** symlink
to the LLVM-19 per-arch sysroot:

```sh
cd "$PREFIX/ohos-sdk/linux/native"
rm -rf sysroot
ln -s "../../../llvm-19/sysroot/aarch64-linux-ohos" sysroot
```

**The symlink MUST be relative**, not absolute. The build runs inside a
docker container that mounts the repo at a different absolute path
(`/work/...`) than the host (`/home/runner/...`). An absolute target
dangles inside the container; a relative target resolves correctly in
both.

`ci/setup-ohos-ndk.sh` handles this automatically.

## Cross-compiling CMake libraries

Once the NDK is set up, CMake cross-compilation is one line:

```sh
cmake \
  -DOHOS_ARCH=arm64-v8a \
  -DOHOS_PLATFORM=OHOS \
  -DCMAKE_TOOLCHAIN_FILE=$PREFIX/ohos-sdk/linux/native/build/cmake/ohos.toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  ...
```

**Do NOT hand-write your own `toolchain.cmake`** — the reference impl
burned 5 CI iterations on try_compile failures, missing crt objects,
and zlib detection issues. The official `ohos.toolchain.cmake` handles
all of that.

## Cross-compiling Botan (not CMake)

enprot depends on Botan, which uses its own `configure.py` (Python),
not CMake. See `ci/build-botan-ohos.sh`:

```sh
python3 ./configure.py \
  --cc=clang \
  --cc-bin=$NDK/llvm/bin/aarch64-unknown-linux-ohos-clang++ \
  --cc-abi-flags="--target=aarch64-linux-ohos --sysroot=$SYSROOT" \
  --cpu=aarch64 \
  --os=linux \
  --build-targets=static \
  --minimized-build \
  --enable-modules=$BOTAN_MODULES \
  --prefix=$PREFIX/ohos-aarch64
```

Static build (`--build-targets=static`) sidesteps `.so` code signing
entirely — important because enprot is a CLI binary, not a loaded
library.

## Static-link zlib

OHOS ships zlib under the SONAME `libshared_libz.z.so`, not `libz.so`.
CMake's `find_package(ZLIB)` won't find it. Options:

1. **Static-link zlib** (recommended): build zlib from source with the
   same `ohos.toolchain.cmake`, link the resulting `libz.a` into your
   library. Side-effect: no runtime libz dependency at all.
2. `patchelf --replace-needed libz.so.1 libshared_libz.z.so` on the
   final `.so`. Fragile, modifies bytes post-build.

enprot's Botan build doesn't link zlib (the module set doesn't include
compression), so this isn't currently a concern. If you add a Botan
module that pulls in zlib, build it statically.

## Code signing (mandatory for `.so` files)

Production OHOS devices refuse to load unsigned `.so` files. Sign with
the NDK's `binary-sign-tool`:

```sh
$PREFIX/ohos-sdk/linux/toolchains/lib/binary-sign-tool sign \
  -selfSign 1 \
  -inFile libfoo.so \
  -outFile libfoo.so   # in-place
```

`-selfSign 1` produces a self-signed cert. Sufficient for OHOS userland
load and for most app distribution. Production Huawei-managed
deployments may require re-signing with an enrolled cert.

enprot's static Botan build means there's no `.so` to sign for the
binary itself. If you produce a Rust `.so` (e.g., via `cdylib` crate
type) for NAPI integration, sign it.

## CI topology

The OHOS NDK binaries (clang, binary-sign-tool) are **x86_64 ELF**,
even though the target is arm64. The simplest viable topology:

```yaml
runs-on: ubuntu-latest
steps:
  - run: sudo apt install cmake ninja-build zlib1g-dev curl jq unzip
  - run: sh ci/setup-ohos-ndk.sh --prefix ext/ohos/ndk
  - run: sh ci/build-botan-ohos.sh --prefix ext/ohos/ndk
  - run: cargo build --target aarch64-linux-ohos --release
  - run: docker run --privileged --rm tonistiigi/binfmt --install arm64
  - run: docker run --rm --platform linux/arm64 ghcr.io/hqzing/dockerharmony:latest ./ohos-smoke
```

`ci/setup-ohos-ndk.sh` + `ci/build-botan-ohos.sh` + `.github/workflows/ohos.yml`
implement this for enprot. The NDK (~4 GB combined) is cached across CI
runs via `actions/cache@v4` keyed on the setup script's hash.

## Verification with dockerharmony

`dockerharmony` is a Docker image of real OHOS userland (musl + toybox +
mksh) extracted from an official OpenHarmony release. It runs
aarch64-linux-musl binaries natively on arm64 hosts, or via qemu
binfmt on x86_64.

`ci/ohos-smoke.c` round-trips a SHA-3 hash and an AES-256-GCM AEAD
operation via Botan's C API to confirm the static lib actually links
and runs on the target.

## Pitfalls summary

The reference impl's 18-iteration journey:

| # | Lesson |
| --- | --- |
| 1 | The SDK tarball ALREADY contains `ohos-sdk/` at top level. Extract into `$PREFIX`, not `$PREFIX/ohos-sdk`. |
| 2 | The SDK has MULTIPLE zips (`toolchains-*.zip`, `native-*.zip`). Unzip `*.zip`, not just one. |
| 3 | `ohos.toolchain.cmake` is at `native/build/cmake/`, not `build/cmake/`. |
| 4 | Use the NDK's bundled `ohos.toolchain.cmake` — do NOT hand-write your own. |
| 5 | `update-binfmts --enable qemu-x86_64` lacks the F flag. Use `tonistiigi/binfmt --install` instead. |
| 6 | Host-level binfmt needs the FULL x86_64 userland. Rabbit hole — use docker instead. |
| 7 | `ohos-sysroot.tar.gz` already contains `sysroot/` at top level. Don't `mkdir sysroot && tar -C sysroot`. |
| 8 | The OHOS CDN (`cidownload.openharmony.cn`) resets connections. Always use `curl --retry 5 --retry-all-errors`. |
| 9 | The SDK's sysroot is MULTIARCH. The toolchain expects PER-ARCH. Use the LLVM-19 per-arch sysroot. |
| 10 | `ln -s` interprets relative targets relative to the SYMLINK's location, not cwd. Resolve `$PREFIX` to absolute first. |
| 11 | Symlinks created on the host break inside docker containers if absolute targets don't match the container's mount path. Use relative symlink targets. |
| 12 | Cache the NDK (~4 GB combined) across CI runs via `actions/cache@v4` keyed on `setup-ndk.sh` hash. |

## What this does NOT verify

- **Real OHOS hardware.** dockerharmony runs OHOS rootfs on a Linux kernel;
  real devices may have additional constraints (kernel-level code signing,
  SELinux policies).
- **Enrollment signing.** `-selfSign 1` is self-signed. Production
  Huawei-managed deployments may require re-signing with an enrolled cert.
- **HNP packaging** for HarmonyOS PC distribution. See
  <https://www.cnblogs.com/yangykaifa/p/19479007> for the HNP packaging
  flow once the binary builds.

## References

- OHOS CMake doc: <https://github.com/mengfei0053/openharmony-6.0-app-dev-docs/blob/main/napi/build-with-ndk-cmake.md>
- NDK download pattern: <https://github.com/hqzing/ohos-node/blob/master/build.sh>
- Real OHOS userland container: <https://github.com/hqzing/dockerharmony>
- Reference impl (libpng-ruby): <https://github.com/claricle/libpng-ruby/pull/13>
- ohos-rs (Rust NAPI for OHOS): <https://github.com/ohos-rs/ohos-rs>
