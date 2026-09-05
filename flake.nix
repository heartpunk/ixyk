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
      devShells = nixpkgs.lib.mapAttrs (system: env: let
        pkgs = import nixpkgs { inherit system; };
      in {
        default = env.shell;
        lean = pkgs.mkShell {
          ELAN = "";
          packages = [
            (import ./nix/lean.nix { inherit pkgs; })
            (pkgs.python312.withPackages (ps: [ ps.hypothesis ps.z3-solver ]))
            pkgs.zstd
          ];
        };
      }) environments;
      packages = nixpkgs.lib.mapAttrs (system: env: let
        pkgs = import nixpkgs { inherit system; };
        reapi = import ./nix/reapi.nix { inherit pkgs; development = env.package; };
      in {
        default = env.package;
        dev-environment = env.package;
        lean = import ./nix/lean.nix { inherit pkgs; };
      } // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
        inherit reapi;
        docker-image = import ./nix/docker-image.nix {
          inherit pkgs reapi;
          development = env.package;
        };
      }) environments;
    };
}
