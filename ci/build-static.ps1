$BOTAN_MODULES = "$($(get-content 'ci\botan-modules') -join ',')"

. $(Join-Path 'ci\build-static\pre' "$Env:TARGET.ps1")

# install cross
&{
  $ErrorActionPreference = 'Continue'
  & cargo install --version "$Env:CROSS_VERSION" cross
}
# update version in manifest to match our tag
(Get-Content Cargo.toml) |
  %{ $_ -replace '^version.*',"version = `"$Env:RELEASE_TAG`"" } |
  Set-Content .\Cargo.toml

# build
&{
  $ErrorActionPreference = 'Continue'
  & cross -vv build --target "$Env:TARGET" --release
}

. $(Join-Path 'ci\build-static\post' "$Env:TARGET.ps1")

