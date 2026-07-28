$BOTAN_MODULES = "$($(get-content 'ci\botan-modules') -join ',')"
$ErrorActionPreference = "Stop"

# setup msvc compiler environment
$vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vspath = & "$vswhere" -latest -property installationPath
Import-Module "$vspath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "$vspath" -DevCmdArguments '-arch=x64 -no_logo' -SkipAutomaticLocation

if (-not $Env:PREFIX) {
    $Env:PREFIX = (Join-Path $PWD 'botan-install').Replace('\', '/')
}
$WORKDIR = $PWD

# -------------------- 0. BZip2 (librnp find_package REQUIRED) --------------------
# librnp's src/lib/CMakeLists.txt calls find_package(BZip2 REQUIRED)
# unconditionally — even with ENABLE_BZIP2=OFF. Chocolatey's bzip2
# only ships the exe + DLL, not a .lib. Build from source instead.
$bzip2Ver = "1.0.8"
& curl -fsSL "https://github.com/libarchive/bzip2/archive/refs/tags/bzip2-$bzip2Ver.tar.gz" -o bzip2.tar.gz
tar -xzf bzip2.tar.gz
$bzip2Dir = Get-ChildItem -Directory -Filter "bzip2-*" | Select-Object -First 1
Push-Location -LiteralPath $bzip2Dir.FullName
# bzip2's Makefile is Unix-oriented. For MSVC we compile the single
# source file that produces the library.
& cl /O2 /MT /c blocksort.c huffman.c crctable.c randtable.c compress.c decompress.c bzlib.c
& lib /OUT:bzip2.lib blocksort.obj huffman.obj crctable.obj randtable.obj compress.obj decompress.obj bzlib.obj
# Install headers + lib into PREFIX
New-Item -ItemType Directory -Force -Path "$Env:PREFIX/include" | Out-Null
New-Item -ItemType Directory -Force -Path "$Env:PREFIX/lib" | Out-Null
Copy-Item bzlib.h "$Env:PREFIX/include/"
Copy-Item bzip2.lib "$Env:PREFIX/lib/"
$Env:BZIP2_INCLUDE_DIR = "$Env:PREFIX/include"
$Env:BZIP2_LIBRARY = "$Env:PREFIX/lib/bzip2.lib"
Pop-Location

# -------------------- 0b. ZLIB (librnp find_package REQUIRED) --------------------
$zlibVer = "1.3.1"
& curl -fsSL "https://github.com/madler/zlib/releases/download/v$zlibVer/zlib-$zlibVer.tar.gz" -o zlib.tar.gz
tar -xzf zlib.tar.gz
$zlibDir = Get-ChildItem -Directory -Filter "zlib-*" | Select-Object -First 1
Push-Location -LiteralPath $zlibDir.FullName
# zlib has a CMake build — use it for MSVC compatibility.
New-Item -ItemType Directory -Force -Path build | Out-Null
Push-Location build
& cmake .. `
    -DCMAKE_INSTALL_PREFIX="$Env:PREFIX" `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
& cmake --build . --config Release --parallel $Env:NUMBER_OF_PROCESSORS
& cmake --install . --config Release
Pop-Location
Pop-Location
$Env:ZLIB_ROOT = "$Env:PREFIX"

# -------------------- 1. Botan (static, MT runtime) --------------------
& git clone --depth 1 --branch "$Env:BOTAN_VERSION" https://github.com/randombit/botan
Push-Location -LiteralPath botan
& python .\configure.py --prefix="$Env:PREFIX" --without-documentation `
  --build-targets=static --minimized-build `
  --enable-modules="$BOTAN_MODULES" --msvc-runtime=MT `
  --cc=msvc --os=windows
&{
  $ErrorActionPreference = 'Continue'
  nmake install
}
Pop-Location

# -------------------- 2. JSON-C (librnp hard dep) --------------------
& git clone --depth 1 --branch json-c-0.17-20230812 https://github.com/json-c/json-c.git "$WORKDIR\json-c-src"
New-Item -ItemType Directory -Force -Path "$WORKDIR\json-c-src\build" | Out-Null
Push-Location -LiteralPath "$WORKDIR\json-c-src\build"
& cmake .. `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_SHARED_LIBS=OFF `
    -DBUILD_TESTING=OFF `
    -DCMAKE_INSTALL_PREFIX="$Env:PREFIX" `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
& cmake --build . --config Release --parallel $Env:NUMBER_OF_PROCESSORS
& cmake --install . --config Release
Pop-Location

# -------------------- 3. librnp --------------------
$RNP_VERSION = "0.18.1"
& git clone --branch "v$RNP_VERSION" --depth 1 https://github.com/rnpgp/rnp.git "$WORKDIR\rnp-src"
Push-Location -LiteralPath "$WORKDIR\rnp-src"
& git submodule update --init --recursive
Pop-Location

New-Item -ItemType Directory -Force -Path "$WORKDIR\rnp-src\build" | Out-Null
Push-Location -LiteralPath "$WORKDIR\rnp-src\build"

# Point librnp's CMake at the just-built botan + json-c. Disable the
# features that need botan modules we don't ship (PQC needs DILITHIUM,
# KYBER; crypto-refresh needs HKDF which is enabled but they also want
# the broader refresh surface).
# Point librnp's CMake at the just-built botan + json-c. Provide
# stub dirent.h + getopt.h — rnp's CMake find_path() calls these
# REQUIRED for the CLI tool (src/rnp/), but we only need the library
# (librnp) for rnp-rs. The stubs satisfy find_path without adding
# real POSIX compat code.
# Stub POSIX headers — rnp's src/common/getoptwin.h includes
# <getopt.h> and <dirent.h> which MSVC doesn't have. Put stubs
# directly in PREFIX/include so the compiler finds them via -I.
Set-Content -Path "$Env:PREFIX/include/dirent.h" -Value "/* stub — not used by librnp */"
Set-Content -Path "$Env:PREFIX/include/getopt.h" -Value "/* stub — not used by librnp */"
# Stub getopt.lib — CMake's find_library(GETOPT_LIBRARY getopt) needs
# an actual .lib file even though we never link the CLI. Create a
# minimal empty static lib that satisfies the find_library call.
Set-Content -Path "$Env:PREFIX/include/getopt_stub.c" -Value "int __enprot_getopt_stub(void) { return 0; }"
Push-Location "$Env:PREFIX/include"
& cl /c /MT getopt_stub.c 2>&1 | Out-Null
& lib /OUT:"$Env:PREFIX/lib/getopt.lib" getopt_stub.obj 2>&1 | Out-Null
Pop-Location

& cmake .. `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_SHARED_LIBS=OFF `
    -DBUILD_TESTING=OFF `
    -DENABLE_DOC=OFF `
    -DCRYPTO_BACKEND=botan `
    -DENABLE_PQC=OFF `
    -DENABLE_CRYPTO_REFRESH=OFF `
    -DENABLE_COMPRESSION=OFF `
    -DENABLE_BZIP2=OFF `
    -DENABLE_ZLIB=OFF `
    -DCMAKE_INSTALL_PREFIX="$Env:PREFIX" `
    -DBOTAN_INCLUDE_DIR="$Env:PREFIX/include/botan-3" `
    -DBOTAN_LIBRARY="$Env:PREFIX/lib/botan-3.lib" `
    -DJSON-C_INCLUDE_DIR="$Env:PREFIX/include/json-c" `
    -DJSON-C_LIBRARY="$Env:PREFIX/lib/json-c.lib" `
    -DDIRENT_INCLUDE_DIR="$Env:PREFIX/include" `
    -DGETOPT_INCLUDE_DIR="$Env:PREFIX/include" `
    -DGETOPT_LIBRARY="$Env:PREFIX/lib/getopt.lib" `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
if ($LASTEXITCODE -ne 0) { throw "librnp cmake configure failed" }

# Build ONLY the librnp target, not the CLI tools (rnp/rnpkeys).
# The CLI needs dirent.h/getopt.h (stubs above satisfy find_path
# but not actual compilation of CLI source).
& cmake --build . --config Release --target librnp --parallel $Env:NUMBER_OF_PROCESSORS
if ($LASTEXITCODE -ne 0) { throw "librnp cmake build failed" }

# Install just the library + headers.
& cmake --install . --config Release --component Headers
& cmake --install . --config Release --component Libraries
if ($LASTEXITCODE -ne 0) { throw "librnp cmake install failed" }

Pop-Location

# -------------------- 4. Tell rnp-rs where to find it --------------------
# rnp-rs's build.rs reads RNP_INCLUDE_DIR / RNP_LIB_DIR if set;
# otherwise falls back to /usr/include (Linux/macOS only).
$Env:RNP_INCLUDE_DIR = "$Env:PREFIX/include"
$Env:RNP_LIB_DIR     = "$Env:PREFIX/lib"
echo "RNP_INCLUDE_DIR=$Env:RNP_INCLUDE_DIR" | Out-File -Append -Encoding ascii $Env:GITHUB_ENV
echo "RNP_LIB_DIR=$Env:RNP_LIB_DIR"         | Out-File -Append -Encoding ascii $Env:GITHUB_ENV

# Cargo config: static-link botan-3 into the enprot binary.
New-Item -ItemType Directory -Force -Path '.cargo'
$TARGET = "x86_64-pc-windows-msvc"
$config = @"
[target.$TARGET.botan-3]
rustc-link-search = ["native=$Env:PREFIX/lib"]
rustc-link-lib = ["static=botan-3"]
[target.$TARGET.rnp-0]
rustc-link-search = ["native=$Env:PREFIX/lib"]
rustc-link-lib = ["static=rnp-0"]
"@
Set-Content -Path ".cargo\config" -Value $config

# Sanity check: rnp.h must be present.
$Expected = Join-Path $Env:PREFIX "include/rnp/rnp.h"
if (-not (Test-Path $Expected)) {
    throw "librnp header missing at $Expected"
}
Write-Host "==> Botan + json-c + librnp built and installed to $Env:PREFIX"
