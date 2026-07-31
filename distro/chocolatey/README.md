# enprot on Chocolatey

Windows package manager (Chocolatey) package for enprot. Installs
the prebuilt `x86_64-pc-windows-msvc` binary from GitHub Releases
and shims `enprot.exe` onto `PATH`.

## Install

```powershell
choco install enprot -y
enprot --version
```

## Build + publish (maintainers)

The package is built and published automatically by
`.github/workflows/deploy.yml` on every release tag. Manual publish
is supported via:

```powershell
cd distro\chocolatey
$env:PACKAGE_VERSION = "0.5.13"
choco pack enprot.nuspec --version $env:PACKAGE_VERSION
choco push enprot.$env:PACKAGE_VERSION.nupkg --api-key $env:CHOCOLATEY_API_KEY
```

`PACKAGE_CHECKSUM` (SHA256 of the upstream zip) is optional; CI sets
it automatically from the GitHub Releases artifact.

## Layout

```
distro/chocolatey/
├── enprot.nuspec                      # package manifest
├── tools/
│   ├── chocolateyinstall.ps1          # download + unzip
│   └── chocolateyuninstall.ps1        # cleanup
└── README.md                          # this file
```

## What it does NOT do

- **Build from source.** Uses the prebuilt binary. Use `cargo
  install enprot` if you need a from-source build.
- **Install Botan/librnp.** The MSVC binary uses `vendored-rnp` +
  statically linked Botan — no runtime deps.
- **Scoop manifest.** Separate, simpler format; tracked as a
  follow-up.
