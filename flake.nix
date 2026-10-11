# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "ixyk AMD64 semantic-model validation spike";

  nixConfig = {
    extra-substituters = [ "https://ixyk.cachix.org" ];
    extra-trusted-public-keys = [ "ixyk.cachix.org-1:BcMtFvSIYCFngmXH/S8028XN4katnbBRoD898nm3g3M=" ];
  };

  inputs = {
    ifrl.url = "git+ssh://git@github.com/heartpunk/ifrl.git?rev=04f9fb38cf205ab091cb690b6b58f711b65edf54";
    nixpkgs.follows = "ifrl/nixpkgs";
    angr-nix = {
      follows = "ifrl/angr-nix";
    };
  };

  outputs = { nixpkgs, angr-nix, ifrl, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      environments = nixpkgs.lib.genAttrs systems (system:
        import (ifrl.outPath + "/nix/clients/ixyk/nix/dev-environment.nix") { inherit nixpkgs angr-nix ifrl system; });
    in {
      devShells = nixpkgs.lib.mapAttrs (_: env: { default = env.shell; }) environments;
      packages = nixpkgs.lib.mapAttrs (system: env: let
        pkgs = import nixpkgs { inherit system; };
        reapi = ifrl.lib.worker {
          inherit pkgs;
          python = pkgs.python312;
          developmentEnvironment = env.package;
          component = "ixyk";
          workerContract = "ixyk-e7a3ca80-python312-lean430-procns-v1";
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
