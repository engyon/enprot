# Chocolatey install script for enprot.
#
# Triggered by `choco install enprot`. Queries the GitHub Releases
# API to find the canonical asset URL for the requested version
# (handles both post-split `enprot-vX.Y.Z` and legacy `vX.Y.Z` tag
# shapes), downloads it, and unzips into the package's tools/
# directory. Chocolatey automatically shimms any *.exe found in
# tools/ so `enprot` ends up on PATH.

$ErrorActionPreference = 'Stop'

$version = $env:PACKAGE_VERSION
if (-not $version) {
    throw "PACKAGE_VERSION env var must be set by the CI workflow before invoking choco pack"
}

# Strip any non-digit prefix (matches deploy.yml's tag-stripping logic).
$version = $version -replace '^[^0-9]+', ''
$assetName = "enprot-v$version-x86_64-pc-windows-msvc.zip"

# Resolve the asset URL via the GitHub Releases API.
# Try post-split tag (enprot-vX.Y.Z) first, fall back to legacy (vX.Y.Z).
$url = $null
foreach ($prefix in @('enprot-v', 'v')) {
    $tag = "$prefix$version"
    $apiUrl = "https://api.github.com/repos/engyon/enprot/releases/tags/$tag"
    Write-Host "Querying GitHub API: $apiUrl"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Headers @{
            'Accept'               = 'application/vnd.github+json'
            'User-Agent'           = 'chocolatey-enprot'
            'X-GitHub-Api-Version' = '2022-11-28'
        } -ErrorAction Stop
        $match = $response.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
        if ($match) {
            $url = $match.browser_download_url
            Write-Host "Found asset '$assetName' on tag $tag"
            break
        }
    } catch {
        # 404 means the tag doesn't exist; try the next prefix.
        Write-Host "Tag $tag not found (or no assets); trying next prefix."
    }
}

if (-not $url) {
    throw "No GitHub Release artifact '$assetName' found for version $version. Tried tags: enprot-v$version, v$version"
}

Write-Host "Downloading $url"
$packageArgs = @{
    packageName    = 'enprot'
    url64bit       = $url
    unzipLocation  = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
    specificFolder = ''
}
if ($env:PACKAGE_CHECKSUM) {
    $packageArgs['checksum64']    = $env:PACKAGE_CHECKSUM
    $packageArgs['checksumType64'] = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

Write-Host "enprot installed. Try: enprot --version"
