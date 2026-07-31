# Nix flake for enprot — build from source, dev shell, and app.
#
# Usage:
#   nix run github:engyon/enprot/main -- --version
#   nix profile install github:engyon/enprot/main
#
# Or in a flake.nix:
#   inputs.enprot.url = "github:engyon/enprot/main";
#   outputs = { self, enprot, ... }: { packages.x86_64-linux.default = enprot.packages.x86_64-linux.default; };
#
# Dev shell:
#   nix develop

{
  description = "Engyon Protected Text — confidentiality and provenance for text/source files";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }@inputs:
    let
      # System-independent outputs: NixOS module, exported for
      # consumption by any NixOS configuration regardless of
      # architecture. Per-system packages/devShells come from
      # eachDefaultSystem below.
      nixosModules.enprot = import ./nix/module.nix;
      nixosModule = nixosModules.enprot;  # common alias
    in
    {
      inherit nixosModules nixosModule;
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          cmake
          makeWrapper
        ];

        buildInputs = with pkgs; [
          botan
          rnp
        ];

        # Build enprot as a Nix derivation. We disable vendored-rnp
        # because Nixpkgs already provides librnp; system libs are
        # preferred over bundled ones to avoid duplication.
        enprot = pkgs.rustPlatform.buildRustPackage {
          pname = "enprot";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          inherit nativeBuildInputs buildInputs;

          # Tests need the binary built + the FFI's shared lib on the
          # loader path.
          doCheck = true;
          preCheck = ''
            export DYLD_LIBRARY_PATH=${pkgs.lib.makeLibraryPath buildInputs}:$DYLD_LIBRARY_PATH
          '';

          postInstall = ''
            # Shell completions
            mkdir -p $out/share/bash-completion/completions
            mkdir -p $out/share/fish/vendor_completions.d
            mkdir -p $out/share/zsh/site-functions
            $out/bin/enprot completions bash > $out/share/bash-completion/completions/enprot || true
            $out/bin/enprot completions fish > $out/share/fish/vendor_completions.d/enprot.fish || true
            $out/bin/enprot completions zsh  > $out/share/zsh/site-functions/_enprot || true
          '';

          meta = with pkgs.lib; {
            description = "Engyon Protected Text — confidentiality and provenance for text/source files";
            homepage = "https://github.com/engyon/enprot";
            license = licenses.bsd2;
            mainProgram = "enprot";
            platforms = platforms.unix ++ platforms.windows;
          };
        };
      in
      {
        packages.default = enprot;
        packages.enprot = enprot;

        apps.default = flake-utils.lib.mkApp {
          drv = enprot;
          name = "enprot";
        };

        devShells.default = pkgs.mkShell {
          packages = nativeBuildInputs ++ buildInputs ++ (with pkgs; [
            cargo-edit
            cargo-audit
            cargo-deny
            rust-analyzer
            python3    # for the bindings test suite
            nodejs     # for the Node bindings test suite
          ]);
          shellHook = ''
            echo "enprot dev shell — $(enprot --version 2>/dev/null || echo 'binary not built yet; run: cargo build --release')"
          '';
        };
      });
}
