# Enprot on NixOS

The Nix flake at the repo root ships a NixOS module that installs
enprot system-wide and (optionally) registers git filters in
`/etc/gitconfig` so any user on the machine gets EPT-aware git
automatically.

## Enable

```nix
# flake.nix in your NixOS config
{
  inputs.enprot.url = "github:engyon/enprot/main";
  outputs = { self, nixpkgs, enprot, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        enprot.nixosModules.enprot
        ./configuration.nix
      ];
    };
  };
}

# configuration.nix
{ ... }:
{
  services.enprot.enable = true;
  services.enprot.gitFilter = true;          # default: true
  services.enprot.casdir = "/var/lib/enprot/cas";  # default
}
```

## Options

| Option | Default | Description |
|---|---|---|
| `services.enprot.enable` | `false` | Activate the system-level service. |
| `services.enprot.casdir` | `/var/lib/enprot/cas` | System CAS directory. |
| `services.enprot.gitFilter` | `true` | Register git filters in `/etc/gitconfig`. |
| `services.enprot.package` | `pkgs.enprot` | Override the enprot package. |

## What it does

1. Adds `enprot` to `environment.systemPackages`.
2. Creates `${casdir}` with mode 0755 via `systemd.tmpfiles`.
3. If `gitFilter` is true (default), adds the following to `/etc/gitconfig`:
   - `filter.enprot.clean` — runs `enprot encrypt-store` on `git add`
   - `filter.enprot.smudge` — runs `enprot decrypt` on `git checkout`
   - `diff.enprot.textconv` — runs `enprot decrypt` for `git diff`
   - `merge.enprot.driver` — calls the EPT merge driver on conflicts

Users opt in per-repo via `.gitattributes`:

```
*.ept  filter=enprot diff=enprot merge=enprot
*.toml filter=enprot diff=enprot merge=enprot
```

## What it doesn't do

- **Per-user encryption keys.** Each user manages their own
  `ENPROT_WORD` env var (or interactive prompt). The system module
  doesn't ship a key custody solution.
- **Background daemon.** enprot runs as a CLI on demand. A future
  release may ship a Confium-backed daemon for distributed trust.
- **macOS (nix-darwin).** This module targets NixOS Linux. A
  nix-darwin module is a separate effort.
