# setup msvc compiler environment
$vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vspath = & "$vswhere" -latest -property installationPath
Import-Module "$vspath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "$vspath" -DevCmdArguments '-arch=x64 -no_logo' -SkipAutomaticLocation

# build botan
& git clone --depth 1 --branch "$Env:BOTAN_VERSION" https://github.com/randombit/botan
Push-Location -LiteralPath botan
& python .\configure.py --prefix="$Env:PREFIX" --without-documentation `
  --without-openssl --build-targets=static --minimized-build `
  --enable-modules="$BOTAN_MODULES" --msvc-runtime=MT `
  --cc=msvc --os=windows --library-suffix=-2
&{
  $ErrorActionPreference = 'Continue'
  nmake install
}
Pop-Location

# override for static linking
New-Item -ItemType Directory -Force -Path '.cargo'
Write-Output @"
[target.$Env:TARGET.botan-2]
rustc-link-search = ["native=${Env:PREFIX}/lib"]
rustc-link-lib = ["static=botan-2"]
"@ | Out-File -Append -Encoding UTF8 -LiteralPath .cargo\config

