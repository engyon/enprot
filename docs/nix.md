# NixOS / Nix flake

[`nix run`][nix-run] the binary, install it via [`nix profile install`][nix-profile],
or use the dev shell via [`nix develop`][nix-develop].

[nix-run]: https://nix.dev/manual/nix/2.22/command-ref/new-cli/nix3-run
[nix-profile]: https://nix.dev/manual/nix/2.22/command-ref/new-cli/nix3-profile
[nix-develop]: https://nix.dev/manual/nix/2.22/command-ref/new-cli/nix3-develop

## Run

```sh
nix run github:engyon/enprot/main -- --version
```

## Install

```sh
nix profile install github:engyon/enprot/main
enprot --version
```

## Use as a flake input

```nix
# flake.nix in your project
{
  inputs.enprot.url = "github:engyon/enprot/main";
  outputs = { self, enprot, nixpkgs, ... }@inputs: {
    # The enprot package, plus a wrapped binary that includes the
    # librnp/botan runtime deps on its loader path.
    packages.x86_64-linux.default =
      inputs.enprot.packages.x86_64-linux.default;
  };
}
```

## Dev shell

```sh
git clone https://github.com/engyon/enprot
cd enprot
nix develop
cargo build --release
```

The dev shell brings in:
- Rust toolchain (pinned to `rust-toolchain.toml`)
- Botan + librnp (with headers)
- cargo-edit, cargo-audit, cargo-deny, rust-analyzer
- Python + Node.js (for the bindings test suites)

## NixOS module

This flake does not yet ship a NixOS module. A future addition could
expose enprot's `merge-driver` and `clean`/`smudge` git filters as a
system option so any user on a NixOS machine gets EPT-aware git for
free.
