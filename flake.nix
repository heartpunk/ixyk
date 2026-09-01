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
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ angr-nix.overlays.default ];
          };
          python = pkgs.python312.withPackages (ps: [
            ps.angr
            ps.coverage
            ps.hypothesis
            ps.ipykernel
            ps.pytest
          ]);
        in {
          default = pkgs.mkShell {
            packages = [
              python
              pkgs.basedpyright
              pkgs.bazelisk
              pkgs.buildifier
              pkgs.git
              pkgs.jujutsu
              pkgs.ruff
            ];
            PYTHONNOUSERSITE = "1";
            PYTHONSAFEPATH = "1";
          };
        });
    };
}
