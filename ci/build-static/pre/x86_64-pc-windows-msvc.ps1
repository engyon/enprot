# Build the full C dependency stack for Windows MSVC release.
# Reuses ci/install.ps1 (same script as test CI — DRY). install.ps1
# builds bzip2 + zlib + Botan + json-c + librnp from source and sets
# RNP_INCLUDE_DIR / RNP_LIB_DIR / RUSTFLAGS / PREFIX via GITHUB_ENV.

# setup msvc compiler environment
$vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vspath = & "$vswhere" -latest -property installationPath
Import-Module "$vspath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "$vspath" -DevCmdArguments '-arch=x64 -no_logo' -SkipAutomaticLocation

# Delegate to the unified install script (same as test CI).
& ./ci/install.ps1

# install.ps1 exports RUSTFLAGS, and the env var overrides
# .cargo/config.toml target rustflags entirely (cargo precedence),
# so the config's PDB suppression never reaches this build. Fold
# it in here: the vendored C stack makes the release PDB big
# enough that link.exe dies with LNK1201 ('error writing to
# program database'). Release binaries ship stripped anyway.
$Env:RUSTFLAGS = "$Env:RUSTFLAGS -C debuginfo=0 -C link-arg=/DEBUG:NONE"
echo "RUSTFLAGS=$Env:RUSTFLAGS" | Out-File -Append -Encoding ascii $Env:GITHUB_ENV
