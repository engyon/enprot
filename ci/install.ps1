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
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
if ($LASTEXITCODE -ne 0) { throw "librnp cmake configure failed" }

& cmake --build . --config Release --parallel $Env:NUMBER_OF_PROCESSORS
if ($LASTEXITCODE -ne 0) { throw "librnp cmake build failed" }

& cmake --install . --config Release
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
