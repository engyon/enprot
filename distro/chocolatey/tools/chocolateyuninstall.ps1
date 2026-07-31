# Chocolatey uninstall script for enprot.
#
# Removes the extracted binary. Chocolatey automatically removes any
# shims it created during install; this script just cleans up the
# package directory contents that weren't tracked.

$ErrorActionPreference = 'Continue'

$packageDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Get-ChildItem -Path $packageDir -Exclude 'chocolatey*.ps1' |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
