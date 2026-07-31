# 18 — NixOS module

**Priority**: P3
**Status**: specified

## Problem

Nix flake (TODO #204, shipped) lets users `nix profile install` or `nix develop`. But NixOS users want system-level integration: global git-filter registration, system-wide CAS directory, SELinux-friendly paths.

## Goals

- `nixosModules.enprot` export from the flake.
- Configures `services.enprot`:
  - `services.enprot.casdir = "/var/lib/enprot/cas";`
  - `services.enprot.gitFilter = true;` → registers `filter.enprot`, `diff.enprot`, `merge.enprot` in `/etc/gitconfig`.
- Optional `services.enprot.daemon.enable` for a future background service.

## Design

```nix
# enprot/nix/module.nix
{ config, lib, pkgs, ... }:
let
  cfg = config.services.enprot;
in {
  options.services.enprot = {
    enable = lib.mkEnableOption "enprot document confidentiality";

    casdir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/enprot/cas";
      description = "System-wide CAS directory.";
    };

    gitFilter = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Register enprot git filters in /etc/gitconfig.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.enprot ];
    # /etc/gitconfig additions
    programs.git.config = lib.mkIf cfg.gitFilter {
      "filter.enprot.clean"  = "enprot encrypt-store -w SECRET=%ENPROT_WORD";
      "filter.enprot.smudge" = "enprot decrypt       -w SECRET=%ENPROT_WORD";
    };
  };
}
```

## Implementation plan

1. Add `nix/module.nix` to the flake outputs.
2. Export it via `nixosModules.enprot`.
3. Test in `nix build .#nixosModule` + a VM smoke test.
4. Doc: extend `docs/nix.md` with the module options.

## Test plan

- [ ] `nixos-rebuild test` in a VM installs enprot, registers git filters.
- [ ] Cookbook: enable on a NixOS server.

## Out of scope

- Nix-Darwin (macOS) module (separate, similar shape).
- Cross-system sync of `.cas/` (covered by [06-cas-backends]).
