# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "ixyk AMD64 semantic-model validation spike";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/e7a3ca8092b61ff85b6a45bf863ea2b2d6a661b3";
    angr-nix = {
      url = "github:heartpunk/angr-nix/3a7e87c627acdc1116e90892636b8e8d57d209d4";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, angr-nix, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      environments = nixpkgs.lib.genAttrs systems (system:
        import ./nix/dev-environment.nix { inherit nixpkgs angr-nix system; });
    in {
      devShells = nixpkgs.lib.mapAttrs (_: env: { default = env.shell; }) environments;
      packages = nixpkgs.lib.mapAttrs (system: env: {
        default = env.package;
        dev-environment = env.package;
      } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
        reapi = import ./nix/reapi.nix {
          pkgs = import nixpkgs { inherit system; };
          development = env.package;
        };
      }) environments;
    };
}
