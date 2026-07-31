# 20 — Chocolatey package for Windows

**Priority**: P3
**Status**: specified

## Problem

Windows users currently install via:
- `cargo install enprot` (needs Rust toolchain)
- `scoop install enprot` (no manifest published)
- Manual binary download from GitHub Releases

Chocolatey is the dominant Windows package manager. A package would unlock enterprise users who can only install software via Chocolatey + internal repos.

## Goals

- `chocolatey` directory with `enprot.nuspec` + `tools/chocolateyinstall.ps1`.
- Auto-publish on tag push via workflow.
- Same install path: `C:\Program Files\enprot\enprot.exe`.

## Design

```
distro/chocolatey/
├── enprot.nuspec
├── tools/
│   ├── chocolateyinstall.ps1
│   ├── chocolateyuninstall.ps1
│   └── chocolateybeforemodify.ps1
└── README.md
```

`tools/chocolateyinstall.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
$url64 = "https://github.com/engyon/enprot/releases/download/v$ENV:VERSION/enprot-v$ENV:VERSION-x86_64-pc-windows-msvc.zip"
Install-ChocolateyZipPackage -PackageName 'enprot' -Url64bit $url64 -UnzipLocation "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
```

CI:

```yaml
- name: Publish to Chocolatey
  if: matrix.target == 'x86_64-pc-windows-msvc'
  run: |
    choco pack distro/chocolatey/enprot.nuspec --version "$VERSION"
    choco push enprot.$VERSION.nupkg --api-key "$CHOCOLATEY_API_KEY"
```

## Implementation plan

1. Acquire Chocolatey API key (storage: `CHOCOLATEY_API_KEY`).
2. Write the nuspec + install scripts.
3. Add CI job.
4. Document at `distro/chocolatey/README.md`.

## Test plan

- [ ] Local `choco pack` + `choco install` succeeds.
- [ ] `enprot --version` works post-install.
- [ ] Auto-publish on tag succeeds.

## Out of scope

- Scoop manifest (less work, future TODO).
- Winget manifest (different format; revisit when Chocolatey is stable).
