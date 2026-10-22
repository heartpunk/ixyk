# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "ixyk AMD64 semantic-model validation spike";

  nixConfig = {
    extra-substituters = [ "https://ixyk.cachix.org" ];
    extra-trusted-public-keys = [ "ixyk.cachix.org-1:BcMtFvSIYCFngmXH/S8028XN4katnbBRoD898nm3g3M=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/e7a3ca8092b61ff85b6a45bf863ea2b2d6a661b3";
    ifrl = {
      url = "github:heartpunk/ifrl/84cfd2929ce9a3510fc042ca1852326f2d22fcb1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, ifrl, ... }:
    let
      angr-nix = ifrl.lib.angr-nix;
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      environments = nixpkgs.lib.genAttrs systems (system:
        import ./nix/dev-environment.nix { inherit nixpkgs angr-nix ifrl system; });
    in {
      devShells = nixpkgs.lib.mapAttrs (_: env: {
        default = env.shell.overrideAttrs (old: {
          IFRL_ANGR_ENVIRONMENT = old.IXYK_NIX_PYTHON_ROOT;
        });
      }) environments;
      packages = nixpkgs.lib.mapAttrs (system: env: let
        pkgs = import nixpkgs { inherit system; };
        reapi = ifrl.lib.worker {
          inherit pkgs;
          python = pkgs.python312;
          developmentEnvironment = env.package;
          component = "ixyk";
          workerContract = "ixyk-e7a3ca80-python312-lean434-procns-v1";
          clientDependencies = env.package;
          contractProperty = "ixyk-nix-contract";
        };
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
