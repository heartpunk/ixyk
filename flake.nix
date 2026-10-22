# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "ixyk AMD64 semantic-model validation spike";

  nixConfig = {
    extra-substituters = [ "https://ixyk.cachix.org" ];
    extra-trusted-public-keys = [ "ixyk.cachix.org-1:BcMtFvSIYCFngmXH/S8028XN4katnbBRoD898nm3g3M=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/e79d204daf01f8a877f7b2ce7324874ce9c84676";
    ifrl = {
      url = "github:heartpunk/ifrl/d4fdac39e0cfe916cc6d4edcd8043ce9d08cdda4";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, ifrl, ... }:
    let
      lean4-nix = ifrl.lib.lean4-nix;
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      environments = nixpkgs.lib.genAttrs systems (system:
        import ./nix/dev-environment.nix { inherit nixpkgs ifrl lean4-nix system; });
    in {
      devShells = nixpkgs.lib.mapAttrs (_: env: { default = env.shell; }) environments;
      packages = nixpkgs.lib.mapAttrs (system: env: let
        pkgs = import nixpkgs { inherit system; };
        reapi = import ./nix/reapi.nix { inherit pkgs; development = env.package; };
      in {
        default = env.package;
        dev-environment = env.package;
      } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
        inherit reapi;
        docker-image = import ./nix/docker-image.nix {
          inherit pkgs reapi;
          development = env.package;
        };
      }) environments;
    };
}
