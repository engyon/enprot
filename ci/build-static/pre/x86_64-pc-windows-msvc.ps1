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
