# NixOS module for enprot — system-level integration.
#
# Enables enprot system-wide and (optionally) registers git filters
# in /etc/gitconfig so any user on the machine gets EPT-aware git.
#
# Usage in a NixOS configuration:
#
#   { inputs.enprot.url = "github:engyon/enprot/main"; }
#   { services.enprot.enable = true; services.enprot.gitFilter = true; }
#
# See TODO.complete/18-nixos-module for design rationale.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.enprot;
in
{
  options.services.enprot = {
    enable = lib.mkEnableOption "enprot document confidentiality";

    casdir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/enprot/cas";
      description = ''
        System-wide CAS directory. Used as the default `-c` target when
        no per-user casdir is configured. Created automatically with
        mode 0755; sensitive content lives in user-owned directories.
      '';
    };

    gitFilter = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Register enprot git filters (clean/smudge/diff/merge) in
        <literal>/etc/gitconfig</literal>. Any user on the system
        automatically gets EPT-aware git for repositories that opt in
        via <literal>.gitattributes</literal>.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.enprot;
      defaultText = lib.literalExpression "pkgs.enprot";
      description = "The enprot package to use.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # Persist the CAS directory.
    systemd.tmpfiles.rules = [
      "d ${cfg.casdir} 0755 root root -"
    ];

    # Register git filters system-wide.
    programs.git.config = lib.mkIf cfg.gitFilter {
      filter.enprot = {
        clean = "${cfg.package}/bin/enprot encrypt-store -w SECRET=$ENPROT_WORD";
        smudge = "${cfg.package}/bin/enprot decrypt -w SECRET=$ENPROT_WORD";
        required = true;
      };
      diff.enprot = {
        textconv = "${cfg.package}/bin/enprot decrypt -w SECRET=$ENPROT_WORD";
        cachefiles = true;
      };
      merge.enprot = {
        name = "enprot merge driver";
        driver = "${cfg.package}/bin/enprot merge-driver %O %A %B %L %P";
      };
    };
  };

  meta = {
    maintainers = [ lib.maintainers.engyon ];
    doc = ./enprot.md;
  };
}
